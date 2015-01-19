#include <pin.H>
#include <cstdlib>
#include <iostream>
#include <sys/shm.h>

#include "colors.hpp"

// 65536
#define MAP_SIZE (1 << 16)

//  CLI options -----------------------------------------------------------

KNOB<BOOL> Knob_debug(KNOB_MODE_WRITEONCE,  "pintool",
    "debug", "0", "Enable debug mode");

//  Global Vars -----------------------------------------------------------

ADDRINT min_addr = 0;
ADDRINT max_addr = 0;

unsigned char bitmap[MAP_SIZE];
uint8_t *bitmap_shm = 0;

ADDRINT last_id = 0;

//  inlined functions -----------------------------------------------------

inline ADDRINT valid_addr(ADDRINT addr)
{
    if ( addr > min_addr && addr < max_addr )
        return true;

    return false;
}

//  Inserted functions ----------------------------------------------------

VOID TrackBranch(ADDRINT cur_addr)
{
    // Could easily make this a UINT16 I think but if MAP_SIZE changes then a type would have to change. 
    ADDRINT cur_id = ((min_addr - cur_addr) ^ last_id) % MAP_SIZE;
    
    if (Knob_debug) {
        std::cout << "\nCURADDR:  0x" << cur_addr << std::endl;
        std::cout << "rel_addr: " << (cur_addr - min_addr) << std::endl;
        std::cout << "cur_id:  " << cur_id << std::endl;
    }

    if (cur_id > MAP_SIZE) {
        std::cout << red << "ERROR: cur_id too large for map" << cend << std::endl;
        return;
    }

    // allows for debugging without running inside of afl.
    if (bitmap_shm == 0){
        bitmap[cur_id]++;
    }
    else {
        bitmap_shm[cur_id]++;
    }

    last_id = cur_id;
}

// Unused currently but could become a fast call in the future once I have tested it more.
VOID TrackBranchFast(ADDRINT cur_addr)
{
    ADDRINT cur_id = ((min_addr - cur_addr) ^ last_id) % MAP_SIZE;
    bitmap_shm[cur_id]++;
    last_id = cur_id;
}

//  Analysis functions ----------------------------------------------------

VOID Trace(TRACE trace, VOID *v)
{
    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
    {
        for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins))
        {
            // make sure it is in a segment we want to instrument!
            if (valid_addr(INS_Address(ins)))
            {
                if (INS_IsBranch(ins)) {
                    // As per afl-as.c we only care about conditional branches (so no JMP instructions)
                    if (INS_HasFallThrough(ins) || INS_IsCall(ins))
                    {
                        if (Knob_debug) {
                            
                            std::cout << "BRACH: 0x" << INS_Address(ins) << ":\t" << INS_Disassemble(ins) << std::endl;
                        }

                        // Instrument the code.
                        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)TrackBranch,
                            IARG_INST_PTR,
                            IARG_END);
                    }
                }
            }
        }
    }
}

VOID entry_point(VOID *ptr)
{
    /*  Much like the original instrumentation from AFL we only want to instrument the segments of code
     *  from the actual application and not the link and PIN setup itself.
     *
     *  Inspired by: http://joxeankoret.com/blog/2012/11/04/a-simple-pin-tool-unpacker-for-the-linux-version-of-skype/
     */

    IMG img = APP_ImgHead();
    for(SEC sec= IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec))
    {
        // lets sanity check the exec flag 
        // TODO: the check for .text name might be too much, there could be other executable segments we
        //       need to instrument but maybe not things like the .plt or .fini/init
        // IF this changes, we need to change the code in the instrumentation code, save all the base addresses.

        if (SEC_IsExecutable(sec) && SEC_Name(sec) == ".text")
        {
            ADDRINT sec_addr = SEC_Address(sec);
            UINT64  sec_size = SEC_Size(sec);
            
            if (Knob_debug)
            {
                std::cout << "Name: " << SEC_Name(sec) << std::endl;
                std::cout << "Addr: 0x" << sec_addr << std::endl;
                std::cout << "Size: " << sec_size << std::endl << std::endl;
            }

            if (sec_addr != 0)
            {
                ADDRINT high_addr = sec_addr + sec_size;

                if (sec_addr > min_addr || min_addr == 0)
                    min_addr = sec_addr;

                // Now check and set the max_addr.
                if (sec_addr > max_addr || max_addr == 0)
                    max_addr = sec_addr;

                if (high_addr > max_addr)
                    max_addr = high_addr;
            }
        }
    }
    if (Knob_debug)
    {
        std::cout << "min_addr:\t0x" << min_addr << std::endl;
        std::cout << "max_addr:\t0x" << max_addr << std::endl << std::endl;
    }
}

// Main functions ------------------------------------------------

INT32 Usage()
{
    std::cerr << "AFLPIN -- A pin tool to enable blackbox binaries to be fuzzed with AFL on Linux" << std::endl;
    std::cerr << "   -debug --  prints extra debug information." << std::endl;
    return -1;
}

bool setup_shm() {
    if (char *shm_id_str = getenv("__AFL_SHM_ID")) {
        int shm_id;
        shm_id = stoi(shm_id_str);
        std::cout << "shm_id: " << shm_id << std::endl;        
        
        bitmap_shm = reinterpret_cast<uint8_t*>(shmat(shm_id, 0, 0));
        
        if (bitmap_shm == reinterpret_cast<void *>(-1)) {
            std::cout << red << "failed to get shm addr from shmmat()" << cend << std::endl;
            return false;
        }
    }
    else {
        std::cout << red << "failed to get shm_id envvar" << cend << std::endl;
        return false;
    }
    return true;
}


int main(int argc, char *argv[])
{
    if(PIN_Init(argc, argv)){
        return Usage();
    }

    setup_shm();

    PIN_SetSyntaxIntel();
    TRACE_AddInstrumentFunction(Trace, 0);
    PIN_AddApplicationStartFunction(entry_point, 0);
    PIN_StartProgram();

    // AFL_NO_FORKSRV=1
    // We could use this main function to talk to the fork server's fd and then enable the fork server with this tool...
}

