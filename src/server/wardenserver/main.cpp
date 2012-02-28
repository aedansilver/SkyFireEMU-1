/*
 * Copyright (C) 2011-2012 Project SkyFire <http://www.projectskyfire.org/>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 3 of the License, or (at your
 * option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program. If not, see <http://www.gnu.org/licenses/>.
 */

/// \addtogroup Warden SkyFire Daemon
/// @{
/// \file

#include "Common.h"
#include "WardenDaemon.h"

#include "Configuration/Config.h"
#include "Log.h"
#include "SignalHandler.h"
#include "WardenSocket.h"
#include "SystemConfig.h"
#include "revision.h"
#include "Util.h"
#include "LoginDatabase.h"
#include "Database/DatabaseEnv.h"
#include "Database/DatabaseWorkerPool.h"

#include <ace/Get_Opt.h>
#include <ace/Sig_Handler.h>
#include <ace/Dev_Poll_Reactor.h>
#include <ace/TP_Reactor.h>
#include <ace/ACE.h>
#include <ace/Acceptor.h>
#include <ace/SOCK_Acceptor.h>
#include <openssl/opensslv.h>
#include <openssl/crypto.h>

#ifndef _WARDEN_CONFIG
# define _WARDEN_CONFIG  "wardenserver.conf"
#endif //_WARDEN_CONFIG

bool stopEvent = false;                                     // Setting it to true stops the server

LoginDatabaseWorkerPool LoginDatabase;                      ///< Accessor to the realm/login database

// Handle warden-servers termination signals
class WardenServerSignalHandler : public Trinity::SignalHandler
{
public:
    virtual void HandleSignal(int SigNum)
    {
        switch (SigNum)
        {
        case SIGINT:
        case SIGTERM:
            stopEvent = true;
            break;
        }
    }
};

/// Print out the usage string for this program on the console.
void usage(const char *prog)
{
    sLog->outString("Usage: \n %s [<options>]\n"
        "-c config_file           use config_file as configuration file\n\r", prog);
}

// Launch the warden server
extern int main(int argc, char **argv)
{
    // Command line parsing to get the configuration file name
    char const *cfg_file = _WARDEN_CONFIG;
    int c = 1;
    while(c < argc)
    {
        if (strcmp(argv[c], "-c") == 0)
        {
            if (++c >= argc)
            {
                sLog->outError("Runtime-Error: -c option requires an input argument");
                usage(argv[0]);
                return 1;
            }
            else
                cfg_file = argv[c];
        }
        ++c;
    }

    if (!ConfigMgr::Load(cfg_file))
    {
        sLog->outError("Invalid or missing configuration file : %s", cfg_file);
        sLog->outError("Verify that the file exists and has \'[Wardenserver]\' written in the top of the file!");
        return 1;
    }
    sLog->Initialize();

    sLog->outString("%s (warden-daemon)", _FULLVERSION);
    sLog->outString("<Ctrl-C> to stop.\n");
    sLog->outString("Using configuration file %s.", cfg_file);

    sLog->outString(" ");
    sLog->outString("   ______  __  __  __  __  ______ __  ______  ______ ");
    sLog->outString("  /\\  ___\\/\\ \\/ / /\\ \\_\\ \\/\\  ___/\\ \\/\\  == \\/\\  ___\\ ");
    sLog->outString("  \\ \\___  \\ \\  _'-\\ \\____ \\ \\  __\\ \\ \\ \\  __<\\ \\  __\\ ");
    sLog->outString("   \\/\\_____\\ \\_\\ \\_\\/\\_____\\ \\_\\  \\ \\_\\ \\_\\ \\_\\ \\_____\\ ");
    sLog->outString("    \\/_____/\\/_/\\/_/\\/_____/\\/_/   \\/_/\\/_/ /_/\\/_____/ ");
    sLog->outString("  Project SkyFireEmu 2012(c) Open-sourced Game Emulation ");
    sLog->outString("           <http://www.projectskyfire.org/> ");
    sLog->outString(" ");
    sLog->outDetail("Using ACE: %s", ACE_VERSION);

    ACE_Reactor::instance(new ACE_Reactor(new ACE_TP_Reactor(), true), true);

    sLog->outBasic("Max allowed open files is %d", ACE::max_handles());

    // warden-servers PID file creation
    std::string pidfile = ConfigMgr::GetStringDefault("PidFile", "");
    if (!pidfile.empty())
    {
        uint32 pid = CreatePIDFile(pidfile);
        if (!pid)
        {
            sLog->outError("Cannot create PID file %s.\n", pidfile.c_str());
            return 1;
        }

        sLog->outString("Daemon PID: %u\n", pid);
    }

    ///- Launch the listening network socket
    ACE_Acceptor<WardenSocket, ACE_SOCK_Acceptor> acceptor;

    uint16 rmport = ConfigMgr::GetIntDefault("WardenServerPort", 4321);
    std::string bind_ip = ConfigMgr::GetStringDefault("BindIP", "0.0.0.0");

    ACE_INET_Addr bind_addr(rmport, bind_ip.c_str());

    if (acceptor.open(bind_addr, ACE_Reactor::instance(), ACE_NONBLOCK) == -1)
    {
        sLog->outError("Wardenserver can not bind to %s:%d", bind_ip.c_str(), rmport);
        return 1;
    }

    // Initialize the signal handlers
    WardenServerSignalHandler SignalINT, SignalTERM;

    // Register warden-servers signal handlers
    ACE_Sig_Handler Handler;
    Handler.register_handler(SIGINT, &SignalINT);
    Handler.register_handler(SIGTERM, &SignalTERM);

    ///- Handle affinity for multiple processors and process priority on Windows
#ifdef _WIN32
    {
        HANDLE hProcess = GetCurrentProcess();

        uint32 Aff = ConfigMgr::GetIntDefault("UseProcessors", 0);
        if (Aff > 0)
        {
            ULONG_PTR appAff;
            ULONG_PTR sysAff;

            if (GetProcessAffinityMask(hProcess, &appAff, &sysAff))
            {
                ULONG_PTR curAff = Aff & appAff;            // remove non accessible processors

                if (!curAff)
                    sLog->outError("Processors marked in UseProcessors bitmask (hex) %x not accessible for wardenserver. Accessible processors bitmask (hex): %x", Aff, appAff);
                else if (SetProcessAffinityMask(hProcess, curAff))
                    sLog->outString("Using processors (bitmask, hex): %x", curAff);
                else
                    sLog->outError("Can't set used processors (hex): %x", curAff);
            }
            sLog->outString();
        }

        bool Prio = ConfigMgr::GetBoolDefault("ProcessPriority", false);

        if (Prio)
        {
            if (SetPriorityClass(hProcess, HIGH_PRIORITY_CLASS))
                sLog->outString("The wardenserver process priority class has been set to HIGH");
            else
                sLog->outError("Can't set wardenserver process priority class.");
            sLog->outString();
        }
    }
#endif

    sWardend->Initialize();
    // maximum counter for next ping
    uint32 numLoops = (ConfigMgr::GetIntDefault("MaxPingTime", 30) * (MINUTE * 1000000 / 100000));
    uint32 loopCounter = 0;

    // Wait for termination signal
    while (!stopEvent)
    {
        // dont move this outside the loop, the reactor will modify it
        ACE_Time_Value interval(0, 100000);

        if (ACE_Reactor::instance()->run_reactor_event_loop(interval) == -1)
            break;

        if ((++loopCounter) == numLoops)
        {
            loopCounter = 0;
            sLog->outDetail("Ping MySQL to keep connection alive");
            LoginDatabase.KeepAlive();
        }
    }

    sLog->outString("Halting process...");
    return 0;

    // Cleaning up objects in memory
    ACE_Reactor::instance()->close_singleton();
    return 0;
}

