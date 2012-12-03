cnxcc Module

Carlos Ruiz Díaz

   ConexionGroup S.A.

   Copyright © 2012 Carlos Ruiz Díaz, carlos.ruizdiaz@gmail.com
   ____________________________________________________________

   Table of Contents

   1. Admin Guide

        1. Overview
        2. Dependencies

              2.1. Modules

        3. Parameters

              3.1. dlg_flag (integer)

        4. Functions

              4.1. cnxcc_set_max_time()               

        5. Exported RPC Commands

              5.1. cnxcc.active_clients
              5.2. cnxcc.check_client
              5.3. cnxcc.kill_call              

   List of Examples
   
   1.1 
   
Chapter 1. Admin Guide

   Table of Contents

    1. Overview
    2. Dependencies

        2.1. Modules

    3. Parameters

        3.1. dlg_flag (integer)

    4. Functions

        4.1. cnxcc_set_max_time()               

    5. Exported RPC Commands

        5.1. cnxcc.active_clients
        5.2. cnxcc.check_client
        5.3. cnxcc.kill_call
        
1. Overview

   The cnxcc module was created to limit call duration in a multiple-calls/single-client scenario where
   a single client, identified by a unique value, is making several calls at the same time and consuming 
   its remaining seconds at a rate that is equal to the number of concurrent calls the client is having.

   This module was conceived to fix a business rule problem the company I work for was having, but since 
   this problem is rather general than specific we (at ConexionGroup) decided to release the code 
   considering that the community might find it useful.
   
   Cnxcc can be used if your billing software does not mantain the state of the calls it authorizes. 
   In these cases, a call passes through the Authorization phase to the "active" state and while it is 
   still established, another call comes in following the same path and in the step of deciding whether
   the client has or not credit left, the authorizer program fails to determine the right value because the 
   first call is still online and naturally, not stop-billing signal (SIP BYE message) was received 
   to account the amount of talked time which is used to calculate the new credit value.
   
   In common cases, both calls will end before the credit is fully exhausted and in this case, no money is lost,
   but when the credit is about to end but still available, a call can easily consume more credit than it has 
   because the authorizer has to control over it. In this particular cases Cnxcc can help you ...
   
   The module has the ability to shutdown all calls when the credit is completely exhausted and to inform via
   a event route the call being killed. This information can be used to perform back-office operation such as 
   billing, logging, RTP proxy tear down, etc.

   # INCOMPLETE, WORK IN PROGRESS #
   
