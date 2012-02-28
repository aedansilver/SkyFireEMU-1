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

#ifndef _WARDEN_MGR_H
#define _WARDEN_MGR_H

#include "Common.h"
#include "SharedDefines.h"
#include "Define.h"
#include "WardenProtocol.h"
#include "WorldSession.h"
#include "Util.h"
#include "BigNumber.h"
#include "WorldPacket.h"
#include "Opcodes.h"

#include <ace/Singleton.h>
#include <ace/Connector.h>
#include <ace/SOCK_Connector.h>
#include <ace/SOCK_Stream.h>
#include <ace/Svc_Handler.h>
#include <ace/Dev_Poll_Reactor.h>
#include <ace/Reactor.h>
#include <openssl/sha.h>

// Definition of ratio of check types (based on a long session of 1162 checks)
// They are cumulative, meaning that I add the %age to the previous one
#define WCHECK_PAGE1_RATIO  25.0f   // 36.5
#define WCHECK_PAGE2_RATIO  50.0f   // 36.5
#define WCHECK_MEMORY_RATIO 94.0f   // 21.0
#define WCHECK_DRIVER_RATIO 97.4f   // 03.4
#define WCHECK_FILE_RATIO   98.7f   // 01.3
#define WCHECK_LUA_RATIO   100.0f   // 01.3

// State machine for warden activity on one session
enum WardenClientState
{
    WARD_STATE_UNREGISTERED,
    WARD_STATE_LOAD_MODULE,
    WARD_STATE_LOAD_FAILED,
    WARD_STATE_TRANSFORM_SEED,
    WARD_STATE_CHEAT_CHECK_IN,
    WARD_STATE_CHEAT_CHECK_OUT,
    WARD_STATE_USER_DISABLED,
    WARD_STATE_PENDING_WARDEN,
    WARD_STATE_NEED_WARDEN,
};

class WardenSvcHandler: public ACE_Svc_Handler <ACE_SOCK_STREAM, ACE_NULL_SYNCH>
{
    public:
        typedef struct WardenMgrCmd
        {
            WardenOpcode cmd;
            bool (WardenSvcHandler::*handler)(void);
        } WardenHandler;

        // Daemon replies related
        bool _HandleDisconnect();
        bool _HandlePong();
        bool _HandleNewKeys();

        ACE_SOCK_Stream* Peer;
        int open(void*);
        int handle_input(ACE_HANDLE);

    private:
};

typedef ACE_Connector<WardenSvcHandler, ACE_SOCK_CONNECTOR> WardenConnector;

class WardenMgr
{
    public:
        WardenMgr();
        ~WardenMgr();

        void Initialize(const char* addr, u_short port, bool IsBanning);
        void SetDisabled() { _Enabled = false; }
        bool IsEnabled() { return _Enabled; }

        // Update
        void Update(uint32 diff);                               // Global Warden System update for packets send/receive
        void Update(WorldSession* const session);               // Session specific update

        // Connection Management
        void Pong();
        void SetDisconnected();

        void Register(WorldSession* const session);

        void SendLoadModuleRequest(WorldSession* const session);
        void SendModule(WorldSession* const session);
        void SendSeedAndComputeKeys(WorldSession* const session);
        void SendSeedTransformRequest(WorldSession* const session);

        bool ValidateTSeed(WorldSession* const session, const uint8 *codedClientTSeed);
        void ChangeClientKey(WorldSession* const session);
        void SendWardenData(WorldSession* const session);

        bool ValidateCheatCheckResult(WorldSession* const session, WorldPacket& clientPacket);
        void Unregister(WorldSession* const session);
        void ReactToCheatCheckResult(WorldSession* const session, bool result);

    private:
        void SendPing();

        // Structure to store checks
        struct MemoryCheckEntry
        {
            std::string String;
            uint32 Offset;
            uint8 Length;
            uint8 Result[20];
        };

        struct PageCheckEntry
        {
            uint32 Seed;
            uint8 SHA[20];
            uint32 Offset;
            uint8 Length;
        };

        struct FileCheckEntry
        {
            std::string String;
            uint8 SHA[20];
        };

        struct LuaCheckEntry
        {
            std::string String;
        };

        struct DriverCheckEntry
        {
            uint32 Seed;
            uint8 SHA[20];
            std::string String;
        };

        struct ModuleCheckEntry
        {
            uint32 Seed;
            uint8 SHA[20];
        };

        struct GenericCheck
        {
            uint8 check;
            union
            {
                MemoryCheckEntry* mem;
                PageCheckEntry* page;
                FileCheckEntry* file;
                LuaCheckEntry* lua;
                DriverCheckEntry* driver;
                ModuleCheckEntry* module;
            };
        };

        typedef std::vector<uint8> WardenCheckMap; // store the check ids
        typedef std::map<std::string, WardenCheckMap> WardenModuleMap; // module md5/check ids

        typedef std::vector<MemoryCheckEntry> WardenMemoryChecks;
        typedef std::vector<PageCheckEntry> WardenPageChecks;
        typedef std::vector<FileCheckEntry> WardenFileChecks;
        typedef std::vector<LuaCheckEntry> WardenLuaChecks;
        typedef std::vector<DriverCheckEntry> WardenDriverChecks;
        //typedef std::vector<ModuleCheckEntry> WardenModulehecks;

        typedef std::vector<GenericCheck> WardenClientCheckList;

        void SendCheatCheck(WorldSession* const session);

        MemoryCheckEntry *GetRandMemCheck();
        PageCheckEntry *GetRandPageCheck();
        FileCheckEntry *GetRandFileCheck();
        LuaCheckEntry *GetRandLuaCheck();
        DriverCheckEntry *GetRandDriverCheck();

        uint32 BuildChecksum(const uint8* data, uint32 dataLen);

        void LoadModuleAndGetKeys(WorldSession* const session);

        bool InitializeCommunication();
        bool LoadFromDB();
        bool CheckModuleExistOnDisk(const std::string &md5);
        void RandAModuleMd5(std::string *result);

        void StartForSession(WorldSession* const session);
        void SetInitialKeys(const uint8 *bSessionKey1, const uint8 *bSessionKey2, uint8* ClientKey, uint8 *ServerKey);

    protected:
        ACE_SOCK_Stream         *_WardenProcessStream;
        ACE_SOCK_Connector      *_WardenProcessConnection;

        bool                    _HalfCall;
        bool                    _Enabled;
        bool                    _PingOut;
        bool                    _Disconnected;
        bool                    _Banning;
        std::string             _WardenAddress;
        u_short                 _WardenPort;
        WardenConnector         _Connector;
        IntervalTimer           m_PingTimer;

        WardenModuleMap         _WardenModuleMap;

        WardenMemoryChecks      _WardenMemoryChecks;
        WardenPageChecks        _WardenPageChecks;
        WardenFileChecks        _WardenFileChecks;
        WardenLuaChecks         _WardenLuaChecks;
        WardenDriverChecks      _WardenDriverChecks;
        //WardenModuleChecks    _WardenModuleChecks;
};

#define sWardenMgr ACE_Singleton<WardenMgr, ACE_Null_Mutex>::instance()
#endif
