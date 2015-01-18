#include <pin.H>
#include <iostream>
#include "colors.hpp"

// 65536
#define MAP_SIZE (1 << 16)

//  CLI options -----------------------------------------------------------

KNOB<BOOL> Knob_debug(KNOB_MODE_WRITEONCE,  "pintool",
    "debug", "0", "Enable debug mode");

//  Global Vars -----------------------------------------------------------

typedef enum
{
    ETYPE_INVALID,
    ETYPE_CALL,
    ETYPE_ICALL,
    ETYPE_TCALL,
    ETYPE_BRANCH,
    ETYPE_IBRANCH,
    ETYPE_RETURN,
    ETYPE_LAST
} ETYPE;

ADDRINT min_addr = 0;
ADDRINT max_addr = 0;


// I cant seem to use MAX_SIZE here, derping at C++
unsigned char bitmap[MAP_SIZE];
UINT32 last_id = 0;

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
    std::cout << "\nCURADDR:  0x" << cur_addr << std::endl;

    // TODO: if we ever change the .text check in the segment loading we need to work on this:
    UINT32 cur_id = (cur_addr - min_addr) ^ last_id;

    std::cout << "rel_addr: " << (cur_addr - min_addr) << std::endl;
    std::cout << "cur_id:  " << cur_id << std::endl;

    if (cur_id > MAP_SIZE) {
        std::cout << red << "ERROR: cur_id too large for map, WTF!" << cend << std::endl;
        return;
    }

    bitmap[cur_id]++;
    last_id = cur_id;
}


//  Analysis functions ----------------------------------------------------


VOID TraceBranches(TRACE trace, INS ins)
{
    if (INS_IsBranch(ins) || INS_IsCall(ins))
    {
        // As per afl-as.c we only care about conditional branches (so no JMP instructions)
        if (INS_HasFallThrough(ins) || INS_IsCall(ins))
        {
            if (Knob_debug) {
                
                std::cout << "BRACH: 0x" << INS_Address(ins) << "\t" << INS_Disassemble(ins) << std::endl;
            }

            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)TrackBranch,
                IARG_INST_PTR,
                IARG_END);
        }
    }
}

VOID Trace(TRACE trace, VOID *v)
{
    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
    {
        for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins))
        {
            // make sure it is in a segment we want to instrument!
            if (valid_addr(INS_Address(ins)))
            {
                TraceBranches(trace, ins);
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


INT32 Usage()
{
    std::cerr << "USAGGE TODO" << std::endl;
    return -1;
}


int main(int argc, char *argv[])
{
    if(PIN_Init(argc, argv)){
        return Usage();
    }
    
    std::cout << "MAPSIZE: " << MAP_SIZE << std::endl;

    PIN_SetSyntaxIntel();
    TRACE_AddInstrumentFunction(Trace, 0);
    PIN_AddApplicationStartFunction(entry_point, 0);
    PIN_StartProgram();
}

