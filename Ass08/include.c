#include "include.h"

/* Make the page writable */                      
int make_rw(unsigned long address)                
{                                                 
	unsigned int level;                           
	pte_t *pte = lookup_address(address, &level); 
	if(pte->pte &~ _PAGE_RW)                      
		pte->pte |= _PAGE_RW;                     
	return 0;                                     
}                                                 

/* Make the page write protected */               
int make_ro(unsigned long address)                
{                                                 
	unsigned int level;                           
	pte_t *pte = lookup_address(address, &level); 
	pte->pte = pte->pte &~ _PAGE_RW;              
	return 0;                                     
} 
