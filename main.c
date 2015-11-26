/*
 * Copyright 2015 Giuseppe Perniola
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.  See COPYING for more details.
 */

//Checking if target is AROS
#ifdef __AROS__
    #define MUIMASTER_YES_INLINE_STDARG
    #include <libraries/mui.h>
    #include <proto/exec.h>
    #include <proto/dos.h>
    #include <proto/intuition.h>
    #include <proto/muimaster.h>
    #include <libraries/asl.h>
    #include <libraries/gadtools.h>
    #include <libraries/iffparse.h>
    #include <clib/alib_protos.h>
    #include <libraries/thread.h>
    #include <proto/thread.h>
    
    //struct IntuitionBase *pIntuitionBase = NULL;
#endif

//Checking if target is MorphOS
#ifdef __MORPHOS__
    #include <intuition/classes.h>
    #include <proto/exec.h>
    #include <proto/dos.h>
    #include <libraries/mui.h>
    #include <proto/muimaster.h>
    #include <proto/intuition.h>
    #include <clib/alib_protos.h>
    #include <string.h>
    #include <stdio.h>
    #include <libraries/asl.h>
    #include <libraries/gadtools.h>
    #include <libraries/iffparse.h>
    
    //struct IntuitionBase *pIntuitionBase = NULL;
#endif

//Checking if target is OS4
#ifdef __amigaos4__
    #define __USE_INLINE__
    #define __USE_BASETYPE__
    #include <libraries/mui.h>
    #include <proto/exec.h>
    #include <proto/muimaster.h>
    #include <proto/intuition.h>
    #include <libraries/asl.h>
    #include <libraries/intuition.h>
    #include <libraries/gadtools.h>
    #include <libraries/iffparse.h>
    
    //struct MUIMasterIFace *pIMUIMaster = NULL;
    //struct IntuitionIFace *pIIntuition = NULL;
#endif

//Checking if target is AmigaOS3
#if !defined(__amigaos4__) && !defined(__MORPHOS__) && !defined(__AROS__)
    #include <libraries/mui.h>
    #include <proto/exec.h>
    #include <proto/dos.h>
    #include <proto/muimaster.h>
    #include <libraries/asl.h>
    #include <libraries/gadtools.h>
    #include <libraries/iffparse.h>
    #define IPTR ULONG
    //struct IntuitionBase *pIntuitionBase = NULL;
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <exec/types.h>
#include "miner.h"

//struct Library      *pMUIMasterBase;
struct Library 	    *pThreadBase;

// -----------------------------------------------------------------------------------

extern const char   *algo_names[];
extern bool         opt_benchmark;
extern int          opt_n_threads;
extern int          num_processors;
extern char         *rpc_url;
extern char         *rpc_userpass;
extern char         *rpc_user;
extern char         *rpc_pass;
extern double       *thr_hashrates;
extern enum algos   opt_algo;
extern int          opt_scrypt_n;

extern void stop_work();
extern void restart_work();
extern void *stratum_thread(void *userdata);
extern void *miner_thread(void *userdata);
extern bool check_algo(const char *pAlgo);
extern void set_algo(const char *pAlgo);
extern bool parse_config(json_t *config, const char *pname, const char *ref);
extern bool save_config(const char *pFilename);

// -----------------------------------------------------------------------------------

#define MENU_LOAD_CONFIG    1
#define MENU_SAVE_CONFIG    2
#define MENU_ABOUT          3
#define BUTTON_START        4
#define BUTTON_STOP         5

Object *pApp;
Object *pMainWin;
Object *pLoadConfigMenu;
Object *pSaveConfigMenu;
Object *pAboutMenu;
Object *pQuitMenu;
Object *pURLText;
Object *pUsernameText;
Object *pPasswordText;
Object *pStartButton;
Object *pStopButton;
Object *pCloseButton;
Object *pRequester;
Object *pQuietCheckButton;
Object *pDebugCheckButton;
Object *pProtocolDumpCheckButton;
Object *pBenchmarkButton;
Object *pNoRedirectButton;
Object *pNoGetworkButton;
Object *pNoGBTButton;
Object *pAlgoText;
Object *pRetriesText;
Object *pRetryPauseText;
Object *pScanTimeText;
Object *pTimeoutText;
Object *pProxyText;
Object *pCertText;
Object *pCoinbaseAddrText;
Object *pCoinbaseSigText;

//int func()
//{
//    int operand1, operand2, sum, accumulator;
//    
//    operand1 = 2; 
//    operand2 = 3;
//
//    asm ("mov %1, %%eax\n\t"
//        "mov %2, %%ebx\n\t"
//      	"add %%ebx, %%eax\n\t"
//      	"mov %%eax, %0"
//	       : "=r" (sum)		  /* output operands */
//	       : "r" (operand1), "r" (operand2)
//           : "%eax", "%ebx"); /* input operands */
//    
//    accumulator = sum;
       
//    return accumulator;
//}

BOOL LoadConfig(const char *c_pCompletePath)
{
    char            text[256];
    BOOL            bError = FALSE;
    json_error_t    err;
    json_t          *pConfig;
    
    if (!c_pCompletePath || strlen(c_pCompletePath) <= 0)
    {
        return FALSE;
    }
    
    pConfig = JSON_LOAD_FILE(c_pCompletePath, &err);
	if (json_is_object(pConfig))
	{
        bError = !parse_config(pConfig, PROGRAM_NAME, c_pCompletePath);
        
        set(pURLText, MUIA_String_Contents, rpc_url);
        set(pUsernameText, MUIA_String_Contents, rpc_user);
        set(pPasswordText, MUIA_String_Contents, rpc_pass);
        
        set(pQuietCheckButton, MUIA_Selected, opt_quiet);
        set(pDebugCheckButton, MUIA_Selected, opt_debug);
        set(pProtocolDumpCheckButton, MUIA_Selected, opt_protocol);
        set(pBenchmarkButton, MUIA_Selected, opt_benchmark);
        set(pNoRedirectButton, MUIA_Selected, !opt_redirect);
        set(pNoGetworkButton, MUIA_Selected, !allow_getwork);
        set(pNoGBTButton, MUIA_Selected, !have_gbt);
        
        if (opt_algo == ALGO_SCRYPT)
        {
            sprintf(text, "%s:%d", algo_names[opt_algo], opt_scrypt_n);
        }
        else
        {
            sprintf(text, "%s", algo_names[opt_algo]);
        }
        set(pAlgoText, MUIA_String_Contents, text);
        
        sprintf(text, "%d", opt_retries);
        set(pRetriesText, MUIA_String_Contents, text);
        
        sprintf(text, "%d", opt_fail_pause);
        set(pRetryPauseText, MUIA_String_Contents, text);
        
        sprintf(text, "%d", opt_scantime);
        set(pScanTimeText, MUIA_String_Contents, text);
        
        sprintf(text, "%d", opt_timeout);
        set(pTimeoutText, MUIA_String_Contents, text);
        
        if (opt_proxy)
        {
            set(pProxyText, MUIA_String_Contents, opt_proxy);
        }
        else
        {
            set(pProxyText, MUIA_String_Contents, "");
        }
        
        if (opt_cert)
        {
            set(pCertText, MUIA_String_Contents, opt_cert);
        }
        else
        {
            set(pCertText, MUIA_String_Contents, "");
        }
        
        if (pCoinbase_addr)
        {
            set(pCoinbaseAddrText, MUIA_String_Contents, pCoinbase_addr);
        }
        else
        {
            set(pCoinbaseAddrText, MUIA_String_Contents, "");
        }
        set(pCoinbaseSigText, MUIA_String_Contents, coinbase_sig);
    }
    else
    {
		if (err.line < 0)
		{
			fprintf(stderr, "%s: %s\n", PROGRAM_NAME, err.text);
        }
		else
		{
			fprintf(stderr, "%s: %d: %s\n", PROGRAM_NAME, err.line, err.text);
        }
        
        bError = TRUE;
	}

	json_decref(pConfig);
	
	return !bError;
}

BOOL SaveConfig(const char *c_pCompletePath)
{
    return save_config(c_pCompletePath);
}

void SetUserPass()
{
    if (!rpc_userpass)
    {
		rpc_userpass = malloc(strlen(rpc_user) + strlen(rpc_pass) + 2);
		if (rpc_userpass)
		{
		  sprintf(rpc_userpass, "%s:%s", rpc_user, rpc_pass);
        }
	}
}

void Init()
{
	LoadConfig("default.json");

	SetUserPass();
}

void Cleanup()
{
    if (rpc_url)
    {
        free(rpc_url);
        rpc_url = NULL;
    }
    
    if (rpc_user)
    {
        free(rpc_user);
        rpc_user = NULL;
    }
    
    if (rpc_pass)
    {
        free(rpc_pass);
        rpc_pass = NULL;
    }
    
    if (rpc_userpass)
    {
        free(rpc_userpass);
        rpc_userpass = NULL;
    }
}

BOOL StartMining()
{
    int             i;
    struct thr_info *thr;
    
    restart_work();
    
    memset(&stratum, 0, sizeof(stratum));
    	
    pApplog_lock = CreateMutex();
    pStats_lock = CreateMutex();
    g_pWork_lock = CreateMutex();
    stratum.pSock_lock = CreateMutex();
    stratum.pWork_lock = CreateMutex();

	num_processors = 1;
	
	opt_n_threads = 1;

    work_restart = AllocVec(opt_n_threads * sizeof(*work_restart), MEMF_ANY | MEMF_CLEAR);
	if (!work_restart)
    {
		return FALSE;
    }
    
	thr_info = AllocVec((opt_n_threads + 2) * sizeof(*thr), MEMF_ANY | MEMF_CLEAR);
	if (!thr_info)
	{
		return FALSE;
    }

	thr_hashrates = (double *)AllocVec(opt_n_threads * sizeof(double), MEMF_ANY | MEMF_CLEAR);
	if (!thr_hashrates)
	{
		return FALSE;
    }
    
	if (want_stratum) 
    {
		/* init stratum thread info */
		stratum_thr_id = opt_n_threads + 1;
		thr = &thr_info[stratum_thr_id];
		thr->id = stratum_thr_id;
		thr->q = tq_new();
        if (!thr->q)
        {
            return FALSE;
        }
        
		/* start stratum thread */
        thr->th = CreateThread(stratum_thread, thr);
        if (!thr->th)
        {
            applog(LOG_ERR, "stratum thread create failed");
            return FALSE;
        }
        
        if (have_stratum)
        {
			tq_push(thr_info[stratum_thr_id].q, strdup(rpc_url));
        }
	}
	
	/* start mining threads */
	for (i = 0; i < opt_n_threads; i++) 
    {
		thr = &thr_info[i];
		thr->id = i;
		thr->q = tq_new();
		if (!thr->q)
        {
            return FALSE;
        }
        
        thr->th = CreateThread(miner_thread, thr);
        if (!thr->th)
        {
            applog(LOG_ERR, "thread %d create failed", i);
            return FALSE;
        }
	}

    applog(LOG_INFO, "%d miner threads started, "
		"using '%s' algorithm.",
		opt_n_threads,
		algo_names[opt_algo]);       

    return TRUE;
}

void StopMining()
{
    stop_work();
    
    if (thr_info)
    {
        applog(LOG_INFO, "stopping...");
        
        MUI_Request(pApp, pMainWin, 0, NULL, "OK", "Please wait a moment to clean up all threads!", NULL);
        
        WaitAllThreads();         
        
        applog(LOG_INFO, "stopped!");
        
        FreeVec(thr_info);
        thr_info = NULL;
    }
    
    if (work_restart)
    {
        FreeVec(work_restart);
        work_restart = NULL;
    }

    if (thr_hashrates)
    {
        FreeVec(thr_hashrates);
        thr_hashrates = NULL;
    }
    
    if (pApplog_lock)
    {
        DestroyMutex(pApplog_lock);
        pApplog_lock = NULL;
    }
    
    if (pStats_lock)
    {
        DestroyMutex(pStats_lock);
        pStats_lock = NULL;
    }
    
    if (g_pWork_lock)
    {
        DestroyMutex(g_pWork_lock);
        g_pWork_lock = NULL;
    }
    
    if (stratum.pSock_lock)
    {
        DestroyMutex(stratum.pSock_lock);
        stratum.pSock_lock = NULL;
    }
    
    if (stratum.pWork_lock)
    {
        DestroyMutex(stratum.pWork_lock);
        stratum.pWork_lock = NULL;
    }
    
    SetAttrs(pLoadConfigMenu, MUIA_Menuitem_Enabled, TRUE, TAG_DONE);
    SetAttrs(pSaveConfigMenu, MUIA_Menuitem_Enabled, TRUE, TAG_DONE);
    SetAttrs(pAboutMenu, MUIA_Menuitem_Enabled, TRUE, TAG_DONE);
    
    SetAttrs(pURLText, MUIA_Disabled, FALSE, TAG_DONE);
    SetAttrs(pUsernameText, MUIA_Disabled, FALSE, TAG_DONE);
    SetAttrs(pPasswordText, MUIA_Disabled, FALSE, TAG_DONE);
    
    SetAttrs(pQuietCheckButton, MUIA_Disabled, FALSE, TAG_DONE);
    SetAttrs(pDebugCheckButton, MUIA_Disabled, FALSE, TAG_DONE);
    SetAttrs(pProtocolDumpCheckButton, MUIA_Disabled, FALSE, TAG_DONE);
    SetAttrs(pBenchmarkButton, MUIA_Disabled, FALSE, TAG_DONE);
    SetAttrs(pNoRedirectButton, MUIA_Disabled, FALSE, TAG_DONE);
    SetAttrs(pNoGetworkButton, MUIA_Disabled, FALSE, TAG_DONE);
    SetAttrs(pNoGBTButton, MUIA_Disabled, FALSE, TAG_DONE);
    
    SetAttrs(pAlgoText, MUIA_Disabled, FALSE, TAG_DONE);
    SetAttrs(pRetriesText, MUIA_Disabled, FALSE, TAG_DONE);
    SetAttrs(pRetryPauseText, MUIA_Disabled, FALSE, TAG_DONE);
    SetAttrs(pScanTimeText, MUIA_Disabled, FALSE, TAG_DONE);
    SetAttrs(pTimeoutText, MUIA_Disabled, FALSE, TAG_DONE);
    SetAttrs(pProxyText, MUIA_Disabled, FALSE, TAG_DONE);
    SetAttrs(pCertText, MUIA_Disabled, FALSE, TAG_DONE);
    SetAttrs(pCoinbaseAddrText, MUIA_Disabled, FALSE, TAG_DONE);
    SetAttrs(pCoinbaseSigText, MUIA_Disabled, FALSE, TAG_DONE);
    
    SetAttrs(pStartButton, MUIA_Disabled, FALSE, TAG_DONE);
    SetAttrs(pStopButton, MUIA_Disabled, TRUE, TAG_DONE);
}

Object *MakeCheck(BOOL state, char *label)
{
    return ImageObject,
            ImageButtonFrame,
            MUIA_Text_Contents, label,
            MUIA_InputMode,     MUIV_InputMode_Toggle,
            MUIA_Image_Spec,    MUII_CheckMark,
            MUIA_Background,    MUII_ButtonBack,
            MUIA_ShowSelState,  FALSE,
            MUIA_Selected,      state,
            MUIA_CycleChain,    TRUE,
        End;
}

BOOL IsValidInt(const char *pStr)
{
   if (*pStr == '-')
   {
      ++pStr;
    }
    
   if (!*pStr)
   {
      return FALSE;
   }
    
   while (*pStr)
   {
      if (!isdigit(*pStr))
      {
         return FALSE;
      }
      else
      {
         pStr ++;
      }
   }

   return TRUE;
}

int main(int argc, char *argv[])
{               
    BOOL                    bRunning = TRUE;              
    char                    *pFail = NULL;
    const char              *pURL;
    const char              *pUser;
    const char              *pPass;
    const char              *pAlgo;
    const char              *pRetries;
    const char              *pRetryPause;
    const char              *pScanTime;
    const char              *pTimeout;
    const char              *pProxy;
    const char              *pCert;
    const char              *pCoinbaseAddr;
    const char              *pCoinbaseSig;
    ULONG                   uSignals;
    struct FileRequester    *pReq;
	
    //pMUIMasterBase = OpenLibrary(MUIMASTER_NAME, MUIMASTER_VMIN);
    //pIntuitionBase = (struct IntuitionBase *)OpenLibrary((STRPTR)"intuition.library", 0L);
    pThreadBase = OpenLibrary((STRPTR)"thread.library", 0L);

#ifdef __amigaos4__
    //pIMUIMaster = (struct MUIMasterIFace *)GetInterface(pMUIMasterBase, "main", 1, NULL);
    //pIIntuition = (struct IntuitionIFace *)GetInterface(pIntuitionBase, "main", 1, NULL);
#endif

    //if (!MUIMasterBase) 
    //{
    //    pFail = "Failed to open "MUIMASTER_NAME".";
    //}
  
    //if (!pFail)
    {
        pApp = ApplicationObject,
    	   MUIA_Application_Title,              (IPTR)PROGRAM_NAME,
    	   MUIA_Application_Version,            (IPTR)"$VER: "PROGRAM_NAME" "VERSION" (09.08.15)",
    	   MUIA_Application_Copyright,          (IPTR)"GPLv2",
    	   MUIA_Application_Author,             (IPTR)"Giuseppe Perniola",
    	   MUIA_Application_Description,        (IPTR)"A CPU miner for cryptocurrencies", 
    	  
    	   MUIA_Application_Menustrip,          (IPTR)(MenustripObject,
                MUIA_Family_Child,              (IPTR)(MenuObject,
                MUIA_Menu_Title,                (IPTR)PROGRAM_NAME,
                    MUIA_Family_Child,          (IPTR)(pLoadConfigMenu = MUI_MakeObject(MUIO_Menuitem, "Load config", "L", 0, 0)),
                    MUIA_Family_Child,          (IPTR)(pSaveConfigMenu = MUI_MakeObject(MUIO_Menuitem, "Save config", "S", 0, 0)),
                    MUIA_Family_Child,          (IPTR)(pAboutMenu = MUI_MakeObject(MUIO_Menuitem, "About", "A", 0, 0)),
                    MUIA_Family_Child,          (IPTR)(pQuitMenu = MUI_MakeObject(MUIO_Menuitem, "Quit", "Q", 0, 0)),
                End),
           End),
        
    	   MUIA_Application_Window,             pMainWin = WindowObject,
                MUIA_Window_Title,              (IPTR)PROGRAM_NAME,
    			WindowContents,                 (IPTR)VGroup,
    			    Child,                      (IPTR)VGroup,
    			        MUIA_Frame,             MUIV_Frame_Group,
        			    Child,                  (IPTR)HGroup,
    					   Child,               (IPTR)LLabel("URL"),
    					   Child,               (IPTR)(pURLText = StringObject, StringFrame, MUIA_CycleChain, TRUE, MUIA_String_Format, MUIV_String_Format_Left, End),
                        End,
        				Child,                  (IPTR)HGroup,
    					   Child,               (IPTR)LLabel("Username"),
    					   Child,               (IPTR)(pUsernameText = StringObject, StringFrame, MUIA_CycleChain, TRUE, MUIA_String_Format, MUIV_String_Format_Left, End),
    					   Child,               (IPTR)LLabel("Password"),
    					   Child,               (IPTR)(pPasswordText = StringObject, StringFrame, MUIA_CycleChain, TRUE, MUIA_String_Format, MUIV_String_Format_Left, End),
                        End,
        				Child,                  (IPTR)(MUI_MakeObject(MUIO_HBar, 4)),
        				Child,                  (IPTR)HGroup,
        				    Child,              (IPTR)VGroup,
        				        MUIA_HorizWeight, 80,
        				        MUIA_Group_VertSpacing, 6,
        				        Child,          (IPTR)LLabel("Quiet"),
        				        Child,          (IPTR)LLabel("Debug"),
        				        Child,          (IPTR)LLabel("Protocol dump"),
        				        Child,          (IPTR)LLabel("Benchmark"),
        				        Child,          (IPTR)LLabel("No redirect"),
        				        Child,          (IPTR)LLabel("No getwork"),
        				        Child,          (IPTR)LLabel("No GBT"),
        				    End,
        				    Child,              (IPTR)VGroup,
        				        Child,          (IPTR)(pQuietCheckButton = MakeCheck(opt_quiet, "Quiet")),
        				        Child,          (IPTR)(pDebugCheckButton = MakeCheck(opt_debug, "Debug")),
                                Child,          (IPTR)(pProtocolDumpCheckButton = MakeCheck(opt_protocol, "Protocol dump")),
                                Child,          (IPTR)(pBenchmarkButton = MakeCheck(opt_benchmark, "Benchmark")),
                                Child,          (IPTR)(pNoRedirectButton = MakeCheck(!opt_redirect, "No redirect")),
                                Child,          (IPTR)(pNoGetworkButton = MakeCheck(!allow_getwork, "No getwork")),
                                Child,          (IPTR)(pNoGBTButton = MakeCheck(!have_gbt, "No GBT")),
        				    End,
        				    Child,              (IPTR)(MUI_MakeObject(MUIO_VBar, 4)),
        				    Child,              (IPTR)VGroup,
        				        MUIA_HorizWeight, 40,
        				        MUIA_Group_VertSpacing, 9,
        				        Child,          (IPTR)LLabel("Algo"),
        				        Child,          (IPTR)LLabel("Retries"),
        				        Child,          (IPTR)LLabel("Retry pause"),
        				        Child,          (IPTR)LLabel("Scan time"),
        				        Child,          (IPTR)LLabel("Timeout"),
        				        Child,          (IPTR)LLabel("Proxy"),
        				        Child,          (IPTR)LLabel("Cert"),
        				        Child,          (IPTR)LLabel("Coinbase addr"),
        				        Child,          (IPTR)LLabel("Coinbase sig"),
        				    End,
        				    Child,              (IPTR)VGroup,
        				        Child,          (IPTR)(pAlgoText = StringObject, StringFrame, MUIA_CycleChain, TRUE, MUIA_String_Format, MUIV_String_Format_Left, End),
        				        Child,          (IPTR)(pRetriesText = StringObject, StringFrame, MUIA_CycleChain, TRUE, MUIA_String_Format, MUIV_String_Format_Left, End),
        				        Child,          (IPTR)(pRetryPauseText = StringObject, StringFrame, MUIA_CycleChain, TRUE, MUIA_String_Format, MUIV_String_Format_Left, End),
        				        Child,          (IPTR)(pScanTimeText = StringObject, StringFrame, MUIA_CycleChain, TRUE, MUIA_String_Format, MUIV_String_Format_Left, End),
        				        Child,          (IPTR)(pTimeoutText = StringObject, StringFrame, MUIA_CycleChain, TRUE, MUIA_String_Format, MUIV_String_Format_Left, End),
        				        Child,          (IPTR)(pProxyText = StringObject, StringFrame, MUIA_CycleChain, TRUE, MUIA_String_Format, MUIV_String_Format_Left, End),
        				        Child,          (IPTR)(pCertText = StringObject, StringFrame, MUIA_CycleChain, TRUE, MUIA_String_Format, MUIV_String_Format_Left, End),
        				        Child,          (IPTR)(pCoinbaseAddrText = StringObject, StringFrame, MUIA_CycleChain, TRUE, MUIA_String_Format, MUIV_String_Format_Left, End),
        				        Child,          (IPTR)(pCoinbaseSigText = StringObject, StringFrame, MUIA_CycleChain, TRUE, MUIA_String_Format, MUIV_String_Format_Left, End),
        				    End,
        				End,
    				End,
                    Child,                      (IPTR)HGroup,
                        MUIA_Frame,             MUIV_Frame_Group,
                        MUIA_Group_SameSize,    TRUE,
                        Child,                  (IPTR)(pStartButton = MUI_MakeObject(MUIO_Button, "Start", NULL)),
                        Child,                  (IPTR)(pStopButton = MUI_MakeObject(MUIO_Button, "Stop", NULL)),
    				    Child,                  (IPTR)(pCloseButton = MUI_MakeObject(MUIO_Button, "Close", NULL)),
                    End,		
    			End,
    		End,
    	End;
    
    	if (!pApp)
    	{
            pFail = "Failed to create MUI Application object.";
        }
    }
    //else 
    //{
    //    pApp = NULL;
    //}

    if (!pFail)
    {
        DoMethod(pMainWin, MUIM_Notify, MUIA_Window_CloseRequest, TRUE, pApp, 2, MUIM_Application_ReturnID, MUIV_Application_ReturnID_Quit);
        
        DoMethod(pLoadConfigMenu, MUIM_Notify, MUIA_Menuitem_Trigger, MUIV_EveryTime, (IPTR)pApp, 2, MUIM_Application_ReturnID, MENU_LOAD_CONFIG);
        DoMethod(pSaveConfigMenu, MUIM_Notify, MUIA_Menuitem_Trigger, MUIV_EveryTime, (IPTR)pApp, 2, MUIM_Application_ReturnID, MENU_SAVE_CONFIG);
        DoMethod(pAboutMenu, MUIM_Notify, MUIA_Menuitem_Trigger, MUIV_EveryTime, (IPTR)pApp, 2, MUIM_Application_ReturnID, MENU_ABOUT);
        DoMethod(pQuitMenu, MUIM_Notify, MUIA_Menuitem_Trigger, MUIV_EveryTime, (IPTR)pApp, 2, MUIM_Application_ReturnID, MUIV_Application_ReturnID_Quit);
        
        DoMethod(pStartButton, MUIM_Notify, MUIA_Pressed, FALSE, pApp, 2, MUIM_Application_ReturnID, BUTTON_START);
        DoMethod(pStopButton, MUIM_Notify, MUIA_Pressed, FALSE, pApp, 2, MUIM_Application_ReturnID, BUTTON_STOP);
        DoMethod(pCloseButton, MUIM_Notify, MUIA_Pressed, FALSE, pApp, 2, MUIM_Application_ReturnID, MUIV_Application_ReturnID_Quit);

        // Input loop...
    	set(pMainWin, MUIA_Window_Open, TRUE);// open window
    	
    	//printf("sizeof(uint8): %d\n", sizeof(uint8_t));
    	//printf("sizeof(uint16): %d\n", sizeof(uint16_t));
    	//printf("sizeof(uint32): %d\n", sizeof(uint32_t));
    	
    	SetAttrs(pStopButton, MUIA_Disabled, TRUE, TAG_DONE);
    	
    	Init();
    	
    	while (bRunning)
    	{
    		ULONG uID = DoMethod(pApp, MUIM_Application_Input, &uSignals);
    
    		switch (uID)
    		{
    		    case MUIV_Application_ReturnID_Quit:
                    bRunning = FALSE;
    			
                    break;	
                    
                case MENU_LOAD_CONFIG:
                    pReq = MUI_AllocAslRequestTags(ASL_FileRequest,
                        ASLFR_Window,           pRequester,
                        ASLFR_TitleText,        "Load configuration",
                        ASLFR_InitialDrawer,    "",
                        ASLFR_InitialFile,      "",
                        ASLFR_InitialPattern,   "#?.json",
                        ASLFR_DoPatterns,       TRUE,
                        ASLFR_RejectIcons,      TRUE,
                        ASLFR_DoSaveMode,       FALSE,
                        TAG_DONE);
                    if (pReq)
                    {
                        if (MUI_AslRequestTags(pReq, TAG_DONE))
                        {
                            char completePath[1024];
                    		
                    		strncpy(completePath, pReq->fr_Drawer, 1024); 
                            AddPart(completePath, pReq->fr_File, 1024); 
                            
                            if (strlen(completePath) > 0)
                            {
                                if (LoadConfig(completePath))
                                {   
                                    MUI_Request(pApp, pMainWin, 0, NULL, "OK", "Configuration file successfully loaded.", NULL);
                                }
                                else
                                {
                                    MUI_Request(pApp, pMainWin, 0, NULL, "OK", "Error occurred during loading of configuration file!", NULL);
                                }
                            }
                        }
                    }
                    
                    break;
                    
                case MENU_SAVE_CONFIG:
                    pReq = MUI_AllocAslRequestTags(ASL_FileRequest,
                        ASLFR_Window,           pRequester,
                        ASLFR_TitleText,        "Save configuration",
                        ASLFR_InitialDrawer,    "",
                        ASLFR_InitialFile,      "default.json",
                        ASLFR_InitialPattern,   "#?.json",
                        ASLFR_DoPatterns,       TRUE,
                        ASLFR_RejectIcons,      TRUE,
                        ASLFR_DoSaveMode,       TRUE,
                        TAG_DONE);
                    if (pReq)
                    {
                        if (MUI_AslRequestTags(pReq, TAG_DONE))
                        {
                            unsigned char completePath[1024];

                    		strncpy(completePath, pReq->fr_Drawer, 1024);
                            AddPart(completePath, pReq->fr_File, 1024);

                            if (strlen(completePath) > 0)
                            {
                                if (SaveConfig(completePath))
                                {
                                    MUI_Request(pApp, pMainWin, 0, NULL, "OK", "Configuration file successfully saved.", NULL);
                                }
                                else
                                {
                                    MUI_Request(pApp, pMainWin, 0, NULL, "OK", "Error occurred during saving of configuration file!", NULL);
                                }
                            }
                        }
                    }
                    
                    break;
                    
                case MENU_ABOUT:
                    MUI_Request(pApp, pMainWin, 0, NULL, "OK", "\33c"PROGRAM_NAME" "VERSION" (09.08.15)\nby Giuseppe Perniola\n\nA CPU miner for cryptocurrencies\nbased on cpuminer v2.4.2", NULL);

                    break;
                    
                case BUTTON_START:
                    pURL = (const char *)XGET(pURLText, MUIA_String_Contents);
                    if (!pURL || strlen(pURL) <= 0 || (strncasecmp(pURL, "stratum+tcp://", 14) && strncasecmp(pURL, "stratum+tcps://", 15)))
                    {
                        MUI_Request(pApp, pMainWin, 0, NULL, "OK", "You must supply a valid URL!", NULL);
                        
                        continue;
                    }
                    
                    pUser = (const char *)XGET(pUsernameText, MUIA_String_Contents);
                    if (!pUser || strlen(pUser) <= 0)
                    {
                        MUI_Request(pApp, pMainWin, 0, NULL, "OK", "You must supply a valid username!", NULL);

                        continue;
                    }
                    
                    pPass = (const char *)XGET(pPasswordText, MUIA_String_Contents);
                    if (!pPass || strlen(pPass) <= 0)
                    {
                        MUI_Request(pApp, pMainWin, 0, NULL, "OK", "You must supply a valid password!", NULL);

                        continue;
                    }
                    
                    pAlgo = (const char *)XGET(pAlgoText, MUIA_String_Contents);
                    if (!pAlgo || strlen(pAlgo) <= 0 || !check_algo(pAlgo))
                    {
                        MUI_Request(pApp, pMainWin, 0, NULL, "OK", "You must supply a valid algorithm (scrypt:xxx or sha256d)!", NULL);

                        continue;
                    }
                    
                    pRetries = (const char *)XGET(pRetriesText, MUIA_String_Contents);
                    if (!pRetries || strlen(pRetries) <= 0 || !IsValidInt(pRetries) || atoi(pRetries) < -1 || atoi(pRetries) > 9999)
                    {
                        MUI_Request(pApp, pMainWin, 0, NULL, "OK", "You must supply a valid number of retries (-1 to 9999)!", NULL);

                        continue;
                    }
                    
                    pRetryPause = (const char *)XGET(pRetryPauseText, MUIA_String_Contents);
                    if (!pRetryPause || strlen(pRetryPause) <= 0 || !IsValidInt(pRetryPause) || atoi(pRetryPause) < 1 || atoi(pRetryPause) > 9999)
                    {
                        MUI_Request(pApp, pMainWin, 0, NULL, "OK", "You must supply a valid number of retry pause (1 to 9999 seconds)!", NULL);

                        continue;
                    }
                    
                    pScanTime = (const char *)XGET(pScanTimeText, MUIA_String_Contents);
                    if (!pScanTime || strlen(pScanTime) <= 0 || !IsValidInt(pScanTime) || atoi(pScanTime) < 1 || atoi(pScanTime) > 9999)
                    {
                        MUI_Request(pApp, pMainWin, 0, NULL, "OK", "You must supply a valid number of scan time (1 to 9999 seconds)!", NULL);

                        continue;
                    }
                    
                    pTimeout = (const char *)XGET(pTimeoutText, MUIA_String_Contents);
                    if (!pTimeout || strlen(pTimeout) <= 0 || !IsValidInt(pTimeout) || atoi(pTimeout) < 0 || atoi(pTimeout) > 99999)
                    {
                        MUI_Request(pApp, pMainWin, 0, NULL, "OK", "You must supply a valid number of timeout (0 to 99999 seconds)!", NULL);

                        continue;
                    }
                    
                    pProxy = (const char *)XGET(pProxyText, MUIA_String_Contents);
                    
                    pCert = (const char *)XGET(pCertText, MUIA_String_Contents);
                    
                    pCoinbaseAddr = (const char *)XGET(pCoinbaseAddrText, MUIA_String_Contents);
                    if (pCoinbaseAddr && strlen(pCoinbaseAddr) > 0 && !address_to_script(pk_script, sizeof(pk_script), pCoinbaseAddr))
                    {
                        MUI_Request(pApp, pMainWin, 0, NULL, "OK", "You must supply a valid coinbase address!", NULL);

                        continue;
                    }
                    
                    pCoinbaseSig = (const char *)XGET(pCoinbaseSigText, MUIA_String_Contents);
                    if (pCoinbaseSig && strlen(pCoinbaseSig) + 1 > sizeof(coinbase_sig))
                    {
            			MUI_Request(pApp, pMainWin, 0, NULL, "OK", "Coinbase signature too long!", NULL);
                        
                        continue;
            		}
                    
                    Cleanup();

                    rpc_url = strdup(pURL);   
                    rpc_user = strdup(pUser);           
                    rpc_pass = strdup(pPass);
                
                    SetUserPass();
                    
                    opt_quiet = XGET(pQuietCheckButton, MUIA_Selected) != 0;
                    opt_debug = XGET(pDebugCheckButton, MUIA_Selected) != 0;
                    opt_protocol = XGET(pProtocolDumpCheckButton, MUIA_Selected) != 0;
                    opt_benchmark = XGET(pBenchmarkButton, MUIA_Selected) != 0;
                    have_stratum = want_stratum = !opt_benchmark;
                    opt_redirect = !(XGET(pNoRedirectButton, MUIA_Selected) != 0);
                    allow_getwork = !(XGET(pNoGetworkButton, MUIA_Selected) != 0);
                    have_gbt = !(XGET(pNoGBTButton, MUIA_Selected) != 0);
                    
                    set_algo(pAlgo);
                    
                    opt_retries = atoi(pRetries);
                    opt_fail_pause = atoi(pRetryPause);
                    opt_scantime = atoi(pScanTime);
                    opt_timeout = atoi(pTimeout);
                    
                    if (pProxy && strlen(pProxy) > 0)
                    {
                        if (!strncasecmp(pProxy, "socks4://", 9))
                        {
			                 opt_proxy_type = CURLPROXY_SOCKS4;
                        }
		                else if (!strncasecmp(pProxy, "socks5://", 9))
		                {
			                 opt_proxy_type = CURLPROXY_SOCKS5;
                        }
#if LIBCURL_VERSION_NUM >= 0x071200
		                else if (!strncasecmp(pProxy, "socks4a://", 10))
		                {
			                 opt_proxy_type = CURLPROXY_SOCKS4A;
                        }
		                else if (!strncasecmp(pProxy, "socks5h://", 10))
		                {
			                 opt_proxy_type = CURLPROXY_SOCKS5_HOSTNAME;
                        }
#endif
		                else
		                {
			                 opt_proxy_type = CURLPROXY_HTTP;
                        }
                        if (opt_proxy)
                        {
                		     free(opt_proxy);
                        }
                		opt_proxy = strdup(pProxy);
                    }
                    else
                    {
                        opt_proxy_type = CURLPROXY_HTTP;
                        if (opt_proxy)
                        {
                            free(opt_proxy);
                            opt_proxy = NULL;
                        }
                    }
                    
                    if (pCert && strlen(pCert) > 0)
                    {
                        if (opt_cert)
                        {
                            free(opt_cert);
                        }
                        opt_cert = strdup(pCert);
                    }
                    else
                    {
                        if (opt_cert)
                        {
                            free(opt_cert);
                            opt_cert = NULL;
                        }
                    }
                    
                    if (pCoinbaseAddr && strlen(pCoinbaseAddr) > 0)
                    {
                        if (pCoinbase_addr)
                        {
                            free(pCoinbase_addr);
                        }
                        pCoinbase_addr = strdup(pCoinbaseAddr);
                        pk_script_size = address_to_script(pk_script, sizeof(pk_script), pCoinbase_addr);
                    }
                    else
                    {
                        if (pCoinbase_addr)
                        {
                            free(pCoinbase_addr);
                            pCoinbase_addr = NULL;
                        }
                        pk_script_size = 0;
                        pk_script[0] = '\0';
                    }
                    if (pCoinbaseSig && strlen(pCoinbaseSig) > 0)
                    {
                        strcpy(coinbase_sig, pCoinbaseSig);
                    }
                    else
                    {
                        coinbase_sig[0] = '\0';
                    }
                    
                    if (StartMining())
                    {
                        SetAttrs(pLoadConfigMenu, MUIA_Menuitem_Enabled, FALSE, TAG_DONE);
                        SetAttrs(pSaveConfigMenu, MUIA_Menuitem_Enabled, FALSE, TAG_DONE);
                        SetAttrs(pAboutMenu, MUIA_Menuitem_Enabled, FALSE, TAG_DONE);
                        
                        SetAttrs(pURLText, MUIA_Disabled, TRUE, TAG_DONE);
                        SetAttrs(pUsernameText, MUIA_Disabled, TRUE, TAG_DONE);
                        SetAttrs(pPasswordText, MUIA_Disabled, TRUE, TAG_DONE);
                        
                        SetAttrs(pQuietCheckButton, MUIA_Disabled, TRUE, TAG_DONE);
                        SetAttrs(pDebugCheckButton, MUIA_Disabled, TRUE, TAG_DONE);
                        SetAttrs(pProtocolDumpCheckButton, MUIA_Disabled, TRUE, TAG_DONE);
                        SetAttrs(pBenchmarkButton, MUIA_Disabled, TRUE, TAG_DONE);
                        SetAttrs(pNoRedirectButton, MUIA_Disabled, TRUE, TAG_DONE);
                        SetAttrs(pNoGetworkButton, MUIA_Disabled, TRUE, TAG_DONE);
                        SetAttrs(pNoGBTButton, MUIA_Disabled, TRUE, TAG_DONE);
                        
                        SetAttrs(pAlgoText, MUIA_Disabled, TRUE, TAG_DONE);
                        SetAttrs(pRetriesText, MUIA_Disabled, TRUE, TAG_DONE);
                        SetAttrs(pRetryPauseText, MUIA_Disabled, TRUE, TAG_DONE);
                        SetAttrs(pScanTimeText, MUIA_Disabled, TRUE, TAG_DONE);
                        SetAttrs(pTimeoutText, MUIA_Disabled, TRUE, TAG_DONE);
                        SetAttrs(pProxyText, MUIA_Disabled, TRUE, TAG_DONE);
                        SetAttrs(pCertText, MUIA_Disabled, TRUE, TAG_DONE);
                        SetAttrs(pCoinbaseAddrText, MUIA_Disabled, TRUE, TAG_DONE);
                        SetAttrs(pCoinbaseSigText, MUIA_Disabled, TRUE, TAG_DONE);
                        
                        SetAttrs(pStartButton, MUIA_Disabled, TRUE, TAG_DONE);
                        SetAttrs(pStopButton, MUIA_Disabled, FALSE, TAG_DONE);
                    }
                    else    
                    {
                        StopMining();
                        
                        MUI_Request(pApp, pMainWin, 0, NULL, "OK", "Error occurred during init of mining!", NULL);
                    }
                    
                    break;
                    
                case BUTTON_STOP:
                    StopMining();
                    
                    break;
    		}
    		
    		if (bRunning && uSignals)
            {
                Wait(uSignals);
            }
    	}
    
    	StopMining();
    
    	set(pMainWin, MUIA_Window_Open, FALSE);
    	
    	Cleanup();
    }

    /* Clean up */
    if (pApp)
    {
        MUI_DisposeObject(pApp);
    }
     
    //if (pMUIMasterBase)
    //{
    //    CloseLibrary(pMUIMasterBase);
    //}
    //if (pIntuitionBase)
    //{
    //    CloseLibrary((struct Library *)pIntuitionBase);
    //}
    if (pThreadBase)
    {
        CloseLibrary(pThreadBase);
    }
    
    if (pFail)
    {
        puts(pFail);
        
        exit(20);
    }
#ifdef __amigaos4__
    //if (pIMUIMaster)
    //{
    //    DropInterface((struct Interface *)pIMUIMaster);
    //} 
    //if (pIIntuition)
    //{
    //    DropInterface((struct Interface *)pIIntuition);
    //}
#endif    
    else
    {
        exit(0);
    }
}
