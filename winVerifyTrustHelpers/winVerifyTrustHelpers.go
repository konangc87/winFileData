package winVerifyTrustHelpers

import (
	"syscall"
	"unsafe"

	"C"

	"golang.org/x/sys/windows"
)

var (
	modwintrust = windows.NewLazySystemDLL("wintrust.dll")

	wtHelperProvDataFromStateData  = modwintrust.NewProc("WTHelperProvDataFromStateData")
	wtHelperGetProvSignerFromChain = modwintrust.NewProc("WTHelperGetProvSignerFromChain")
)

type CRYPT_PROVIDER_CERT struct {
	cbStruct             uint32
	PCert                *windows.CertContext // must have its own ref-count!
	fCommercial          C.int
	fTrustedRoot         C.int // certchk policy should set this.
	fSelfSigned          C.int // set in cert provider
	fTestCert            C.int // certchk policy will set
	dwRevokedReason      uint32
	dwConfidence         uint32 // set in the Certificate Provider
	dwError              uint32
	CTL_CONTEXT          unsafe.Pointer
	fTrustListSignerCert C.int
	//
	// The following two are only applicable to Self Signed certificates
	// residing in a CTL.
	pCtlContext   unsafe.Pointer
	dwCtlError    uint32
	fIsCyclic     C.int
	pChainElement *windows.CertChainElement
}

type CRYPT_PROVIDER_SGNR struct {
	cbStruct          uint32
	sftVerifyAsOf     syscall.Filetime     // either today's filetime or the timestamps
	csCertChain       uint32               // use Add2 and Get functions!
	PasCertChain      *CRYPT_PROVIDER_CERT // use Add2 and Get functions!
	dwSignerType      uint32               // set if known by policy
	psSigner          unsafe.Pointer       // must use the pfnAlloc allocator!
	dwError           uint32               // error encounted while building/verifying the signer.
	csCounterSigners  uint32               // use Add2 and Get functions!
	pasCounterSigners unsafe.Pointer       // use Add2 and Get functions!
	pChainContext     *windows.CertChainContext
}

func WtHelperProvDataFromStateData(hStateData windows.Handle) (cryptProviderData unsafe.Pointer, ret error) {
	r0, _, el := syscall.Syscall(wtHelperProvDataFromStateData.Addr(), 1, uintptr(hStateData), 0, 0)
	cryptProviderData = unsafe.Pointer(r0)
	if cryptProviderData == nil {
		ret = el
	}
	return
}

func WtHelperGetProvSignerFromChain(cryptProviderData unsafe.Pointer, idxSigner uint32, fCountSigner uint32, idxCounterSigner uint32) (provSigner *CRYPT_PROVIDER_SGNR, ret error) {
	r0, _, el := syscall.Syscall6(wtHelperGetProvSignerFromChain.Addr(), 4, uintptr(cryptProviderData), uintptr(idxSigner), uintptr(fCountSigner), uintptr(idxCounterSigner), 0, 0)
	provSigner = (*CRYPT_PROVIDER_SGNR)(unsafe.Pointer(r0))
	if provSigner == nil {
		ret = el
	}
	return
}
