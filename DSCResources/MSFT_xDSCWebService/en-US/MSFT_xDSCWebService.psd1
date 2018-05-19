# culture="en-US"
ConvertFrom-StringData @'
    ThrowCertificateThumbprint       = CertificateThumbprint must contain a certificate thumbprint, or "AllowUnencryptedTraffic" to opt-out from being secure.
    ThrowUseSecurityBestPractice     = Error: Cannot use best practice security settings with unencrypted traffic. Please set UseSecurityBestPractices to $false or use a certificate to encrypt pull server traffic.
    FindCertificateBySubjectMultiple = More than one certificate found with subject containing {0} and using template "{1}".
    FindCertificateBySubjectNotFound = Certificate not found with subject containing {0} and using template "{1}".
'@
