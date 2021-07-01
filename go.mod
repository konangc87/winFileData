module winFileDataSample

go 1.16

replace winFileData => ./winFileData

require (
	golang.org/x/sys v0.0.0-20210630005230-0f9fa26af87c // indirect
	winFileData v0.0.0-00010101000000-000000000000
	winVerifyTrustHelpers v0.0.0-00010101000000-000000000000 // indirect
)

replace winVerifyTrustHelpers => ./winVerifyTrustHelpers
