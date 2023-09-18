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
 * This file contains the ASCONE trie.
 *
 * Version 0.6.1.2-ASCONE
 * 
 * Changelog:
 * -----------------------------------------------------------------------------
 * 0.6.1.2-ASCONE - 2022/05/07 - hamich
 *                  * Created source based on ASPA_Trie 
 */
#include <stdio.h> /* printf */
#include <stdlib.h> /* exit */
#include <string.h>
#include <stdbool.h>
#include "server/ascone_trie.h"
#include "server/update_cache.h"
#include "server/rpki_handler.h"
#include "server/rpki_queue.h"
#include "util/log.h"

static uint32_t countAsconeTrieNode =0;
static ASCONE_TrieNode* newAsconeTrie(void);
static ASCONE_TrieNode* make_ascone_trienode(char data, char* userData, ASCONE_Object* );
static void free_ascone_trienode(ASCONE_TrieNode* node);
static int search_ascone_trie(ASCONE_TrieNode* root, char* word);
static void emptyAsconeDB(ASCONE_DBManager* self);

int process_ASCONE_EndOfData_main(void* uc, void* handler, uint32_t uid, uint32_t pid, time_t ct);
extern RPKI_QUEUE* getRPKIQueue();
extern uint8_t validateASCONE (PATH_LIST* asPathList, uint8_t length, AS_TYPE asType, 
                    AS_REL_DIR direction, uint8_t afi, uint32_t localAS, ASCONE_DBManager* asconeDBManager, ASCONE_DBManager* aspolicyDBManager);

// API for initialization
//
bool initializeAsconeDBManager(ASCONE_DBManager* asconeDBManager, Configuration* config) 
{
   asconeDBManager->tableRoot = newAsconeTrie();
   asconeDBManager->countAsconeObj = 0;
   asconeDBManager->config = config;
   asconeDBManager->cbProcessEndOfData = process_ASCONE_EndOfData_main;
  
   if (!createRWLock(&asconeDBManager->tableLock))
   {
     RAISE_ERROR("Unable to setup the ascone object db r/w lock");
     return false;
   }

  return true;
}

// delete all db
//
static void emptyAsconeDB(ASCONE_DBManager* self)
{
  acquireWriteLock(&self->tableLock);
  free_ascone_trienode(self->tableRoot);
  self->tableRoot = NULL;
  self->countAsconeObj = 0;
  unlockWriteLock(&self->tableLock);
}


// external api for release db
//
void releaseAsconeDBManager(ASCONE_DBManager* self)
{
  if (self != NULL)
  {
    releaseRWLock(&self->tableLock);
    emptyAsconeDB(self);
  }
}


// generate trie node
//
static ASCONE_TrieNode* newAsconeTrie(void) 
{
  ASCONE_TrieNode *rootNode = make_ascone_trienode('\0', NULL, NULL);
  printf("Debug: newAsconeTrie - rootNode: %u", rootNode);
  return rootNode;
}


// external api for creating db object
//
ASCONE_Object* newASCONEObject(uint32_t provAsn, char *otherAsCone, uint16_t asconeType, uint16_t cAsCount, asConePduEntry* custAsns)
{
  ASCONE_Object *obj = (ASCONE_Object*)calloc(1, sizeof(ASCONE_Object));
  // Index variable for loops
  int idx = 0;
  
  obj->providerAsn = provAsn;
  obj->customerAsCount = cAsCount;
  obj->customerAsns = (asConePduEntry *) calloc(cAsCount, sizeof(asConePduEntry));
  asConePduEntry* curASNS = obj->customerAsns;
  asConePduEntry* curCustAsns = custAsns;

   
  printf("Debug: Created ASCONEObject: %u with number of Customers: %u\n", obj->providerAsn, obj->customerAsCount);
  
  if (obj->customerAsns && curCustAsns)
  {
    for(idx = 0; idx < cAsCount; idx++, curCustAsns++, curASNS++)
    {      
      memcpy(curASNS,curCustAsns, sizeof(asConePduEntry));

      printf("MEMCOPY____: obj->customerAsns->ASN: %u, custAsns->ASN: %u\n",curASNS->ASN, curCustAsns->ASN);
      printf("MEMCOPY____: (ADDR)curASNS: %u\n",curASNS);
    }
  }
  printf("Debug: Check this function if custAsns are working correctly!\n");
  //@TODO: THIS function must be checked

  printf("Debug: New ASCONE OBject created!\n");

  return obj;

}

// delete ascone object
//
bool deleteASCONEObject(ASCONE_DBManager* self, ASCONE_Object *obj)
{
  if(obj)
  {
    if (obj->customerAsns)
    {
      free(obj->customerAsns);
    }
    free (obj);
    self->countAsconeObj--;
    return true;
  }
  return false;
}


// create trie node
//
static ASCONE_TrieNode* make_ascone_trienode(char data, char* userData, ASCONE_Object* obj) 
{
  printf("Debug: make_ascone_trienode: char: %c userdata: %s \n", data, userData);

  // Index for loops
  int idx = 0;
  
  // Allocate memory for a TrieNode
  ASCONE_TrieNode* node = (ASCONE_TrieNode*) calloc (1, sizeof(ASCONE_TrieNode));
  if (!node)
  {
    printf("XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\n");
    printf("Debug: WARNING COULD NOT ALLOCATED ROOT NODE!!!!!\n");
    printf("XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\n");
    return NULL;
  }

  for (idx = 0; idx < N; idx++)
      node->children[idx] = NULL;
  
  node->is_leaf = 0;
  node->data = data;
  node->userData = NULL;
  node->asconeObjects = NULL;
  
  return node;
}

// free node
static void free_ascone_trienode(ASCONE_TrieNode* node) 
{
  // Free the trienode sequence
  int idx = 0;
  for(idx = 0; idx < N; idx++) 
  {
    if (node->children[idx] != NULL) 
    {
      free_ascone_trienode(node->children[idx]);
    }
    else 
    {
      continue;
    }
  }
  free(node);
}

bool compareAsconeObject(ASCONE_Object *obj1, ASCONE_Object *obj2)
{
  if (!obj1 || !obj2)
    return false;

  if (obj1->providerAsn != obj2->providerAsn)
    return false;

  if (obj1->customerAsCount != obj2->customerAsCount)
    return false;

    //@TODO: Compare OtherASCONE from ptr_ascone1 and ptr_ascone2
    printf("Debug: COMPARE OBJECT->TODO: OtherASCONE");
    

  int idx;
  asConePduEntry *ptr_ascone1, *ptr_ascone2;
  ptr_ascone1 = obj1->customerAsns;
  ptr_ascone2 = obj2->customerAsns;
  
  for (idx = 0; idx < obj1->customerAsCount; idx++, ptr_ascone1++, ptr_ascone2++)
  {
    if(ptr_ascone1->ASN != ptr_ascone2->ASN)
      return false;
    if (ptr_ascone1->verified != ptr_ascone2->verified)
      return false;    
  }
  return true;
}



bool delete_TrieNode_AsconeObj (ASCONE_DBManager* self, char* word, ASCONE_Object* obj)
{
  bool bRet = false;
  int idx = 0;

  acquireWriteLock(&self->tableLock);
  ASCONE_TrieNode* temp = self->tableRoot; 
  ASCONE_TrieNode* parent = NULL;
  int position = 0;

  // finding
  for(idx = 0; word[idx] != '\0'; idx++)
  {
    position = word[idx] - '0';
    if (temp->children[position] == NULL)
    {
      temp = NULL;
      break;
    }
    parent = temp;
    temp = temp->children[position];
  }

  // info compare
  if (temp && temp->is_leaf == 1 && temp->asconeObjects 
      && compareAsconeObject(temp->asconeObjects, obj))
  {
    deleteASCONEObject(self, temp->asconeObjects);
    free_ascone_trienode(temp);
    temp = NULL;
    parent->children[position] = NULL;
    bRet = true;
  }

  unlockWriteLock(&self->tableLock);

  return bRet;
}

//  new value insert or substitution according to draft
//
ASCONE_TrieNode* insertAsconeObj (ASCONE_DBManager* self, char* word, char* userData, 
                         ASCONE_Object* obj) 
{
  ASCONE_TrieNode* temp = self->tableRoot; // start with root node
  acquireWriteLock(&self->tableLock);
  int i;

  printf("Debug: insertAsconeObj: word: %s userdata: %s obj-addr: %u\n", word, userData, obj);
  
  for (i=0; word[i] != '\0'; i++) 
  {
    int idx = (int) word[i] - '0';
    printf("index: %02x(%d), word[%d]: %c  \n", idx, idx, i, word[i]);
    if (temp->children[idx] == NULL) {
        // If the corresponding child doesn't exist, simply create that child!
        temp->children[idx] = make_ascone_trienode(word[i], userData, obj);
    }
    else {
        // Do nothing. The node already exists
    }
    // Go down a level, to the child referenced by idx
    temp = temp->children[idx];
  }

  if (temp)
  {
    // At the end of the word, mark this node as the leaf node
    temp->is_leaf = 1;
    temp->userData =  userData;

    // substitution if exist
    if (temp->asconeObjects && temp->asconeObjects != obj)
    {
      deleteASCONEObject(self, temp->asconeObjects);
      countAsconeTrieNode--;
    }
    temp->asconeObjects = obj;

    printf("Debug: insertAsconeObj - obj-Addr: %u\n",obj);
    ASCONE_Object* tmpPDU;
    tmpPDU = obj;
    if(tmpPDU == NULL){
      printf("Debug: WARNING tmpPDU is NULL!!!!!\n");
    }
    printf("Debug: insertAsconeObj - obj->providerAsn: %u\n", tmpPDU->providerAsn);
    printf("Debug: insertAsconeObj - obj->ascone_type: %u\n", tmpPDU->ascone_type);
    printf("Debug: insertAsconeObj - obj->customerAsCount: %u\n", tmpPDU->customerAsCount);
    printf("Debug: insertAsconeObj - obj->customerAsns(ADDR): %u\n", &(tmpPDU->customerAsns));
    printf("Debug: insertAsconeObj - obj->customerAsns->ASN: %u\n", tmpPDU->customerAsns->ASN);

    countAsconeTrieNode++;
    self->countAsconeObj++;
  }

  unlockWriteLock(&self->tableLock);

  return temp;
}

// get total count
//
uint32_t getCountAsconeTrieNode(void)
{
  return countAsconeTrieNode;
}

// search method
//
static int search_ascone_trie(ASCONE_TrieNode* root, char* word)
{
    // Searches for word in the Trie
    ASCONE_TrieNode* temp = root;
    int i=0;
    for(i=0; word[i]!='\0'; i++)
    {
        int position = word[i] - '0';
        if (temp->children[position] == NULL)
            return 0;
        temp = temp->children[position];
    }
    if (temp != NULL && temp->is_leaf == 1)
        return 1;
    return 0;
}

// external api for searching trie
//
ASCONE_Object* findAsconeObject(ASCONE_DBManager* self, char* word)
{
    printf("Debug: findAsconeObject: %s\n", word);

    ASCONE_Object *obj=NULL;
  
    acquireWriteLock(&self->tableLock);
    ASCONE_TrieNode* temp = self->tableRoot; 

    int i;
    for(i=0; word[i]!='\0'; i++)
    {
        int position = word[i] - '0';
        if (temp->children[position] == NULL)
        {
          obj = NULL;
          temp = NULL;
          break;
        }
        temp = temp->children[position];
    }

    if (temp != NULL && temp->is_leaf == 1)
    {
        obj = temp->asconeObjects;
    }
    unlockWriteLock(&self->tableLock);

    return obj;
}

//
//  print all nodes
//
ASCONE_TrieNode* printAllAsconeLeafNode(ASCONE_TrieNode *node)
{
  ASCONE_TrieNode* leaf = NULL;
  uint8_t count=0;

  if (node->is_leaf == 1)
  {
    leaf = node;
    return leaf;
  }

  int childIdx;
  for (childIdx = 0; childIdx < N; childIdx++) 
  {
    if(node->children[childIdx])
    {
      leaf = printAllAsconeLeafNode(node->children[childIdx]);
      if (leaf)
      {
        //printf("++ count: %d i:%d digit: %c user data: %s\n", ++count, i, leaf->data, leaf->userData);
        printf("\n++ count: %d, user data: %s, ASCONE object:%p \n", 
            ++count, leaf->userData, leaf->asconeObjects);

        ASCONE_Object *obj = leaf->asconeObjects;
        if (obj)
        {
          printf("++ provider ASN: %d\n", obj->providerAsn);
          printf("++ customerAsCount : %d\n", obj->customerAsCount);
          printf("++ Address: customer asns : %p\n", obj->customerAsns);
          if (obj->customerAsns)
          {
            int pIdx;
            for(pIdx = 0; pIdx < obj->customerAsCount; pIdx++)
              printf("++ customerAsns[%d]: %d\n", pIdx, obj->customerAsns[pIdx]);
          }
          printf("++ ascone_type: %d\n", obj->ascone_type);
        }
      }
    }
  }

  return NULL;
}



void print_ascone_trie(ASCONE_TrieNode* root) {/*{{{*/
    // Prints the nodes of the trie
    if (!root)
        return;
    ASCONE_TrieNode* temp = root;
    printf("%c -> ", temp->data);
    int i=0;
    for (i=0; i<N; i++) {
        print_ascone_trie(temp->children[i]);
    }
}

void print_ascone_search(ASCONE_TrieNode* root, char* word) {
    printf("Searching for %s: ", word);
    if (search_ascone_trie(root, word) == 0)
        printf("Not Found\n");
    else
        printf("Found!\n");
}/*}}}*/

// 
// external API for db loopkup
//
#define MAX_ASN_LENGTH 7
ASCONE_ValidationResult ASCONE_DB_lookup(ASCONE_DBManager* self, uint32_t customerAsn, 
                                     uint32_t providerAsn)
{
  LOG(LEVEL_DEBUG, FILE_LINE_INFO " ASCONE DB Lookup called");

  char strProvAsn[MAX_ASN_LENGTH] = {};
  sprintf(strProvAsn, "%d", providerAsn);
  printf("Debug: ASCONE_DB_lookup: %u\n", providerAsn);  

  ASCONE_Object *obj = findAsconeObject(self, strProvAsn);

  if (!obj) // if there is no object item
  {
    LOG(LEVEL_INFO, "[db] No provider ASN exist -- Unknown");
    printf("[db] No provider ASN exist -- Unknown\n");
    return ASCONE_RESULT_UNKNOWN;
  }
  else // found object
  {
    LOG(LEVEL_INFO, "[db] provider ASN: %d\n", obj->providerAsn);
    LOG(LEVEL_INFO, "[db] customerAsCount : %d\n", obj->customerAsCount);
    LOG(LEVEL_INFO, "[db] Address: customer asns : %p\n", obj->customerAsns);
    printf("[db] provider ASN: %d\n", obj->providerAsn);
    printf("[db] customerAsCount : %d\n", obj->customerAsCount);
    printf("[db] Address: customer asns : %p\n", obj->customerAsns);
    //LOG(LEVEL_INFO, "[db] afi: %d", obj->afi);

    if (obj->customerAsns)
    {
      int idx = 0;
      asConePduEntry *ptr_ascone = obj->customerAsns;
      
      for (idx = 0; idx < obj->customerAsCount; idx++, ptr_ascone++)
      {
        LOG(LEVEL_INFO, "[db] customerAsns[%d]: %d", idx, 
                        ptr_ascone->ASN);
        if (ptr_ascone->ASN == customerAsn)
        {
          printf("Debug: Customer found with ASN: %d\n", customerAsn);
          LOG(LEVEL_INFO, "[db] Matched -- Valid");
          return ASCONE_RESULT_VALID;
        }
      }

      printf("Debug: Customer NOT found with ASN: %d\n", customerAsn);
      LOG(LEVEL_INFO, "[db] No Matched -- Invalid");
      return ASCONE_RESULT_INVALID;
    }
  }
  return ASCONE_RESULT_UNDEFINED;

}

int process_ASCONE_EndOfData_main(void* uc, void* handler, uint32_t uid, 
                                uint32_t pid, time_t ct)
{
  SRxResult        srxRes;
  srxRes.asconeResult = SRx_RESULT_UNKNOWN;
  srxRes.aspaResult = SRx_RESULT_UNKNOWN;
  srxRes.bgpsecResult = SRx_RESULT_UNKNOWN;
  srxRes.roaResult = SRx_RESULT_UNKNOWN;

  SRxDefaultResult defaultRes;
  time_t lastEndOfDataTime = ct;

  UpdateCache*  uCache      = (UpdateCache*)uc;
  SRxUpdateID   updateID    = (SRxUpdateID) uid;
  uint32_t      pathId      = 0;
  RPKIHandler*  rpkiHandler = (RPKIHandler*)handler;

  LOG(LEVEL_INFO, "=== main process_main_ASCONE_EndOfData UpdateCache:%p rpkiHandler:%p ctime:%u", 
      (UpdateCache*)uCache, (RPKIHandler*)rpkiHandler, ct);

  printf("=== main process_main_ASCONE_EndOfData UpdateCache:%p rpkiHandler:%p ctime:%u\n", (UpdateCache*)uCache, (RPKIHandler*)rpkiHandler, ct);


  if (!getUpdateResult(uCache, &updateID, 0, NULL, &srxRes, &defaultRes, &pathId))
  {
    LOG(LEVEL_WARNING, "Update ID: 0x%08X not found ", updateID);
    printf("Debug: ascone_trie.c - Update ID: 0x%08X not found \n", updateID);
    return 0;
  }
  else
  {
    ASCONE_DBManager* asconeDBManager = rpkiHandler->asconeDBManager;
    ASCONE_DBManager* aspolicyDBManager = rpkiHandler->aspolicyDBManager;
    ASCONE_TrieNode *root = asconeDBManager->tableRoot;

    LOG(LEVEL_INFO, "Update ID: 0x%08X  Path ID: 0x%08X", updateID, pathId);
    printf("Debug: ascone_trie.c - Update ID: 0x%08X  Path ID: 0x%08X\n", updateID, pathId);

    uint8_t old_asconeResult = srxRes.asconeResult; // obtained from getUpdateResult above
    AS_PATH_LIST *aspl = getAspathListFromAspathCache (rpkiHandler->aspathCache, pathId, &srxRes);

    if (aspl)
    {
      uint8_t afi = aspl->afi;  
      if (aspl->afi == 0 || aspl->afi > 2) // if more than 2 (AFI_IP6)
        afi = AFI_IP;                      // set default


      LOG(LEVEL_INFO, "Comparison End of Data time(%u) : AS cache entry updated time (%u)",
          lastEndOfDataTime, aspl->lastModified);
      // timestamp comparison
      //
      printf("Debug: Processing pathId: %08X, updateID: %08X\n", pathId, updateID);
      if (lastEndOfDataTime > aspl->lastModified)
      {
        // call ASCONE validation
        //
        
        printf("Debug: Implement ASCONE validation!!!");
        uint8_t valResult = validateASCONE(aspl->asPathList, 
            aspl->asPathLength, aspl->asType, aspl->asRelDir, afi, aspl->localAS, asconeDBManager, aspolicyDBManager);          

        /*LOG(LEVEL_INFO, FILE_LINE_INFO "\033[92m"" Validation Result: %d "
            "(0:v, 2:Iv, 3:Ud 4:DNU 5:Uk, 6:Uf)""\033[0m", valResult);*/

        // update the last validation time regardless of changed or not
        time_t cTime = time(NULL);
        aspl->lastModified = cTime;

        // modify Aspath Cache with the validation result
        printf("\nDebug: Hand over the ASCONE Validation result to the AspathCache pathId: %08X, valResult: %u\n", pathId, valResult);
        modifyAsconeValidationResultToAspathCache (rpkiHandler->aspathCache, pathId, valResult, aspl);
        
        // modify UpdateCache data and enqueue as well
        if (valResult != aspl->asconeValResult)
        {
          aspl->asconeValResult = valResult;
          srxRes.asconeResult = valResult;

          // UpdateCache change
          modifyUpdateCacheResultWithAsconeVal(uCache, &updateID, &srxRes);
          printf("Debug: ADD modifyUpdateCacheResultWithAsconeVal function!!!\n");
        //@TODO: ADD Function

          // if different values, queuing
          RPKI_QUEUE*      rQueue = getRPKIQueue();
          rq_queue(rQueue, RQ_ASCONE, &updateID);
          LOG(LEVEL_INFO, "rpki queuing for ascone validation [uID:0x%08X]", updateID);
          printf("Debug: ascone_trie.c - rpki queuing for ascone validation [uID:0x%08X]", updateID);
        }
      }
      //
      // in case there is another update cache entry whose path id is same with the previous
      // This prevents from doing ASCONE validation repeatedly with the same AS path list
      //
      else /* if else time comparison */
      {
        // update cache entry with the new value 
        if (old_asconeResult != aspl->asconeValResult)
        {
          LOG(LEVEL_INFO, FILE_LINE_INFO " ASCONE validation result already set and "
              " the existed validation result [%d] in UpdateCache is being updated with a new result[%d]", 
              old_asconeResult, aspl->asconeValResult);
          srxRes.asconeResult = aspl->asconeValResult;

          // modify UpdateCache data as well
          modifyUpdateCacheResultWithAsconeVal(uCache, &updateID, &srxRes);
          
          // if different values, queuing
          RPKI_QUEUE*      rQueue = getRPKIQueue();
          rq_queue(rQueue, RQ_ASCONE, &updateID);
          LOG(LEVEL_INFO, "rpki queuing for ascone validation [uID:0x%08X]", updateID);
        }
      }

    }
    else /* no aspath list */
    {
      LOG(LEVEL_WARNING, "Update 0x%08X is registered for ASCONE but the "
          "AS Path List is not found!", updateID);
    } // end of if aspl

    if (aspl)
      free (aspl);

  }// end of else


  return 1;
}
