##############################################################
#  Makefile for WeakCryptoDetector Pin tool
#  Usage:  nmake PIN_ROOT=C:\pin331
##############################################################

!IFNDEF PIN_ROOT
!ERROR  PIN_ROOT is not set. Run:  nmake PIN_ROOT=C:\pin331
!ENDIF

TOOL_NAME   = weak_crypto_detector
TOOL_SRC    = weak_crypto_detector.cpp

PIN_INC     = $(PIN_ROOT)\source\include\pin
PIN_EXTRAS  = $(PIN_ROOT)\extras
PIN_LIB     = $(PIN_ROOT)\intel64\lib
PIN_LIB_EXT = $(PIN_ROOT)\intel64\lib-ext

CXXFLAGS = /nologo /EHsc /MD /O2 /Gy \
           /DTARGET_WINDOWS /DHOST_IA32E /DTARGET_IA32E \
           /D_UNICODE /DUNICODE \
           /I"$(PIN_INC)" \
           /I"$(PIN_INC)\gen" \
           /I"$(PIN_EXTRAS)\cxx\include" \
           /I"$(PIN_EXTRAS)\components\include" \
           /I"$(PIN_EXTRAS)\xed-intel64\include\xed"

LDFLAGS = /DLL /NOLOGO /NODEFAULTLIB \
          /ENTRY:Ptrace_DllMainCRTStartup \
          /EXPORT:main \
          /BASE:0xC5000000 \
          "$(PIN_LIB)\pin.lib" \
          "$(PIN_LIB)\xed.lib" \
          "$(PIN_LIB_EXT)\c_runtime\pinvm.lib" \
          "$(PIN_LIB_EXT)\crtbeginS.obj" \
          ntdll-64.lib kernel32.lib

all: $(TOOL_NAME).dll

$(TOOL_NAME).dll: $(TOOL_SRC)
	cl $(CXXFLAGS) /LD $(TOOL_SRC) /link $(LDFLAGS) /OUT:$(TOOL_NAME).dll

clean:
	-del /Q *.obj *.dll *.exp *.lib 2>NUL
