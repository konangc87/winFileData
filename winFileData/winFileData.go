package winFileData

import (
	"crypto/sha1"
	"crypto/sha256"
	"debug/pe"
	"encoding/hex"
	"io"
	"os"
	"syscall"
	"unsafe"

	"C"

	"winVerifyTrustHelpers"

	"golang.org/x/sys/windows"
)

var _ unsafe.Pointer

const (
	WSS_GET_SECONDARY_SIG_COUNT = 2
	WSS_VERIFY_SPECIFIC         = 1
)

type EmbeddedCert struct {
	issuer   string
	subject  string
	serial   string
	sha1     string
	sha256   string
	pkSha256 string
}

type FileStats struct {
	fid           uint64
	creation_time uint64
	change_time   uint64
	size          uint64
	links         uint16
	attributes    uint64
}

type FileData struct {
	dosName  string
	realName string
	sha256   string
	stats    FileStats
	certs    []EmbeddedCert
	isPe     bool
}

func GetRealName(fileName string) string {
	deviceName, err := syscall.UTF16FromString(fileName[0:2])
	if err != nil {
		return fileName
	}
	drivesBuff := make([]uint16, windows.MAX_PATH)
	n := uint32(0)
	if n, err = windows.QueryDosDevice(&deviceName[0], &drivesBuff[0], windows.MAX_PATH); err != nil || n <= 0 {
		return fileName
	}
	return syscall.UTF16ToString(drivesBuff) + fileName[2:]
}

func getCertPropertyString(cert *windows.CertContext, property uint32, flags uint32) string {
	if chars := windows.CertGetNameString(cert, property, flags, nil, nil, 0); chars > 0 {
		propName := make([]uint16, chars)
		windows.CertGetNameString(cert, property, flags, nil, &propName[0], chars)
		return windows.UTF16ToString(propName)
	}
	return ""
}

func getCertSerialString(cert *windows.CertContext) string {
	var buffer []uint8
	serialBuffer := C.GoBytes(unsafe.Pointer(cert.CertInfo.SerialNumber.Data), C.int(cert.CertInfo.SerialNumber.Size))
	for i := int(cert.CertInfo.SerialNumber.Size - 1); i >= 0; i-- {
		buffer = append(buffer, uint8(serialBuffer[i]))
	}
	return hex.EncodeToString(buffer)
}

func getFileEmbeddedCert(stateData windows.Handle) (certData EmbeddedCert, err error) {
	if stateData != windows.InvalidHandle {
		provData, err := winVerifyTrustHelpers.WtHelperProvDataFromStateData(stateData)
		if err == nil {
			signer, err := winVerifyTrustHelpers.WtHelperGetProvSignerFromChain(provData, 0, 0, 0)
			if err == nil {
				cert := signer.PasCertChain.PCert
				if cert != nil {
					certBuffer := C.GoBytes(unsafe.Pointer(cert.EncodedCert), C.int(cert.Length))
					sha2 := sha256.New()
					sha1 := sha1.New()
					sha1.Write(certBuffer)
					sha2.Write(certBuffer)
					certData.sha256 = hex.EncodeToString(sha2.Sum(nil))
					certData.sha1 = hex.EncodeToString(sha1.Sum(nil))
					sha2.Reset()
					pkBuffer := C.GoBytes(unsafe.Pointer(cert.CertInfo.SubjectPublicKeyInfo.PublicKey.Data), C.int(cert.CertInfo.SubjectPublicKeyInfo.PublicKey.Size))
					sha2.Write(pkBuffer)
					certData.pkSha256 = hex.EncodeToString(sha2.Sum(nil))
					certData.issuer = getCertPropertyString(cert, windows.CERT_NAME_SIMPLE_DISPLAY_TYPE, windows.CERT_NAME_ISSUER_FLAG)
					certData.subject = getCertPropertyString(cert, windows.CERT_NAME_SIMPLE_DISPLAY_TYPE, 0)
					certData.serial = getCertSerialString(cert)
				}
			}
		}
	}
	return
}

func GetFileEmbeddedCerts(fileName string) (embeddedCerts []EmbeddedCert, err error) {
	path, err := syscall.UTF16PtrFromString(fileName)
	if err != nil {
		return
	}
	trustData := windows.WinTrustData{}
	fileData := windows.WinTrustFileInfo{}
	signatureSettings := windows.WinTrustSignatureSettings{}

	// prepare file data
	fileData.Size = uint32(unsafe.Sizeof(fileData))
	fileData.FilePath = path
	// prepare trust data
	trustData.Size = uint32(unsafe.Sizeof(trustData))
	trustData.UIChoice = windows.WTD_UI_NONE
	trustData.UnionChoice = windows.WTD_CHOICE_FILE
	trustData.FileOrCatalogOrBlobOrSgnrOrCert = unsafe.Pointer(&fileData)
	trustData.StateAction = 1
	trustData.RevocationChecks = windows.WTD_REVOKE_NONE
	trustData.ProvFlags = windows.WTD_REVOCATION_CHECK_END_CERT | windows.WTD_CACHE_ONLY_URL_RETRIEVAL
	//  prepare win trust data
	signatureSettings.Size = uint32(unsafe.Sizeof(signatureSettings))
	signatureSettings.Flags = WSS_GET_SECONDARY_SIG_COUNT | WSS_VERIFY_SPECIFIC
	signatureSettings.Index = 0
	trustData.SignatureSettings = &signatureSettings
	err = windows.WinVerifyTrustEx(windows.InvalidHWND, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, &trustData)
	if err != nil {
		return
	}

	trustData.StateAction = windows.WTD_STATEACTION_CLOSE
	defer windows.WinVerifyTrustEx(windows.InvalidHWND, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, &trustData)

	if err == nil {
		numberofSignatures := trustData.SignatureSettings.SecondarySigs
		if certData, err := getFileEmbeddedCert(trustData.StateData); err == nil {
			embeddedCerts = append(embeddedCerts, certData)
		}
		for v := uint32(1); v <= numberofSignatures; v++ {
			trustData.StateAction = windows.WTD_STATEACTION_CLOSE
			windows.WinVerifyTrustEx(windows.InvalidHWND, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, &trustData)
			signatureSettings.Flags = WSS_GET_SECONDARY_SIG_COUNT | WSS_VERIFY_SPECIFIC
			trustData.SignatureSettings.Index = v
			trustData.SignatureSettings = &signatureSettings
			trustData.StateAction = 1
			err = windows.WinVerifyTrustEx(windows.InvalidHWND, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, &trustData)
			if err == nil {
				if certData, err := getFileEmbeddedCert(trustData.StateData); err == nil {
					embeddedCerts = append(embeddedCerts, certData)
				}
			}
		}
	}
	return
}

func GetFileStats(fileName string) (fileStats FileStats, err error) {
	path, err := syscall.UTF16PtrFromString(fileName)
	if err != nil {
		return
	}
	handle, err := syscall.CreateFile(path, 0, 0, nil, syscall.OPEN_EXISTING, 0, 0)
	if err != nil {
		return
	}
	defer syscall.Close(handle)
	info := syscall.ByHandleFileInformation{}
	if err = syscall.GetFileInformationByHandle(handle, &info); err != nil {
		return
	}
	fileStats.attributes = uint64(info.FileAttributes)
	fileStats.change_time = uint64(info.LastWriteTime.Nanoseconds())
	fileStats.creation_time = uint64(info.CreationTime.Nanoseconds())
	fileStats.fid = uint64(info.FileIndexLow) + uint64(info.FileIndexHigh)<<32
	fileStats.links = uint16(info.NumberOfLinks)
	fileStats.size = uint64(info.FileIndexLow) + uint64(info.FileSizeHigh)<<32

	return
}

func GetFileData(fileName string) (fileData FileData, err error) {
	fileData.stats, err = GetFileStats(fileName)
	if err != nil {
		return
	}

	file, err := os.Open(fileName)
	if err != nil {
		return
	}
	defer file.Close()
	if _, err = pe.NewFile(file); err == nil {
		fileData.isPe = true
	}
	hash := sha256.New()
	if _, err = io.Copy(hash, file); err != nil {
		return
	}
	fileData.sha256 = hex.EncodeToString(hash.Sum(nil))
	fileData.certs, _ = GetFileEmbeddedCerts(fileName)
	fileData.dosName = fileName
	fileData.realName = GetRealName(fileName)
	return
}
