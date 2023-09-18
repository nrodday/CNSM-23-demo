/**
 * This software was developed at the National Institute of Standards and
 * Technology by employees of the Federal Government in the course of
 * their official duties. Pursuant to title 17 Section 105 of the United
 * States Code this software is not subject to copyright protection and
 * is in the public domain.
 * 
 * NIST assumes no responsibility whatsoever for its use by other parties,
 * and makes no guarantees, expressed or implied, about its quality,
 * reliability, or any other characteristic.
 * 
 * We would appreciate acknowledgment if the software is used.
 * 
 * NIST ALLOWS FREE USE OF THIS SOFTWARE IN ITS "AS IS" CONDITION AND
 * DISCLAIM ANY LIABILITY OF ANY KIND FOR ANY DAMAGES WHATSOEVER RESULTING
 * FROM THE USE OF THIS SOFTWARE.
 * 
 * 
 * This software might use libraries that are under GNU public license or
 * other licenses. Please refer to the licenses of all libraries required 
 * by this software.
 *
 * This file contains the ASPA trie header information.
 *
 * Version 0.6.1.2
 * 
 * Changelog:
 * -----------------------------------------------------------------------------
 * 0.6.1.2 - 2021/11/18 - kyehwanl
 *           * Moved static declaration statement from .h into .c file 
 * 0.6.0.0  - 2021/02/26 - kyehwanl
 *          - Created source
 */
#ifndef __ASCONE_TRIE_H__
#define __ASCONE_TRIE_H__

#include <stdint.h>
#include "shared/srx_defs.h"
#include "shared/rpki_router.h"
#include "server/configuration.h"
#include "util/mutex.h"
#include "util/rwlock.h"

// The number of children for each node
// We will construct a N-ary tree and make it a Trie
#define N 10

typedef struct {
  uint32_t providerAsn;
  uint16_t ascone_type;         // Policy or ASCONE
  char OtherASCone[255];
  uint16_t customerAsCount;
  asConePduEntry *customerAsns;
} ASCONE_Object;


typedef struct ASCONE_TrieNode ASCONE_TrieNode;
struct ASCONE_TrieNode {
    // The Trie Node Structure
    // Each node has N children, starting from the root
    // and a flag to check if it's a leaf node
    char data; // Storing for printing purposes only
    ASCONE_TrieNode* children[N];
    int is_leaf;
    void *userData;
    ASCONE_Object *asconeObjects;
};

typedef struct {
  ASCONE_TrieNode*         tableRoot;
  uint32_t          countAsconeObj;
  Configuration*    config;  // The system configuration
  RWLock            tableLock;
  int (*cbProcessEndOfData)(void* uCache, void* rpkiHandler, 
                            uint32_t uid, uint32_t pid, time_t ct);
} ASCONE_DBManager;


ASCONE_TrieNode* insertAsconeObj(ASCONE_DBManager* self, char* word, char* userData, ASCONE_Object* obj);
void print_ascone_trie(ASCONE_TrieNode* root);
bool initializeAsconeDBManager(ASCONE_DBManager* asconeDBManager, Configuration* config);
ASCONE_Object* findAsconeObject(ASCONE_DBManager* self, char* word);
void print_ascone_search(ASCONE_TrieNode* root, char* word);
bool deleteASCONEObject(ASCONE_DBManager* self, ASCONE_Object *obj);
ASCONE_Object* newASCONEObject(uint32_t provAsn, char *otherAsCone, uint16_t asconeType, uint16_t cAsCount, asConePduEntry* custAsns);
ASCONE_ValidationResult ASCONE_DB_lookup(ASCONE_DBManager* self, uint32_t customerAsn, uint32_t providerAsn);
ASCONE_TrieNode* print_ascone_AllLeafNode(ASCONE_TrieNode *node);
bool delete_TrieNode_AsconeObj (ASCONE_DBManager* self, char* word, ASCONE_Object* obj);




#endif // __ASCONE_TRIE_H__ 
