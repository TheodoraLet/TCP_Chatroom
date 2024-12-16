#include "CUnit/Basic.h"


int main()
{

    if (CUE_SUCCESS != CU_initialize_registry())
    return CU_get_error();   // Sets the basic run mode, CU_BRM_VERBOSE will show maximum output of run details

    CU_pSuite pSuite=NULL;
    pSuite=CU_add_suite("chat_test_suite",0,0);
    if(pSuite==NULL)
    {
        CU_cleanup_registry();
        return CU_get_error();
    }

    if(NULL==CU_add_test(pSuite,"chat_test",chat_test));

   // Other choices are: CU_BRM_SILENT and CU_BRM_NORMAL

   CU_basic_set_mode(CU_BRM_VERBOSE);   // Run the tests and show the run summary
   CU_basic_run_tests();
   return CU_get_error();

}

void chat_test()
{
    
}
