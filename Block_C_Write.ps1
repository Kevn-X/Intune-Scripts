# Define the path
$cDrivePath = "C:\"

# Get the security descriptor for the C drive
$securityDescriptor = Get-Acl -Path $cDrivePath

# Define the identity for non-administrators
$nonAdminsIdentity = "BUILTIN\Users"

# Create a rule to deny write access for non-administrators
$denyWriteRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    $nonAdminsIdentity,
    "WriteData",
    "ContainerInherit, ObjectInherit",
    "None",
    "Deny"
)

# Add the rule to the security descriptor
$securityDescriptor.AddAccessRule($denyWriteRule)

# Apply the modified security descriptor to the C drive
Set-Acl -Path $cDrivePath -AclObject $securityDescriptor

Write-Host "Write access denied for non-administrators on the C drive."

Exit