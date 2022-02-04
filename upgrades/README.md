## Upgrades of Intel<sup>®</sup> Security Libraries for Data Center (Intel<sup>®</sup> SecL-DC)

### Intel<sup>®</sup> SecL-DC started supporting upgrades from release v3.5

Following is the matrix of upgrade support for different components in Intel<sup>®</sup> SecL-DC

Latest release: v4.0.2

#### Compatibility Matrix:
| Component (v4) |  CMS                | AAS                    | WPM | KBS                    | TA     | AA | WLA | HVS                    | iHUB | WLS                    |
|-------------|------------------------|------------------------|-----|------------------------|--------|----|-----|------------------------|------|------------------------|
| CMS         | NA                     | NA                     | NA  | NA                     | NA     | NA | NA  | NA                     | NA   | NA                     |
| AAS         | v4.0.0, v4.0.1,v4.0.2,v4.0.2 | NA                     | NA  | NA                     | NA     | NA | NA  | NA                     | NA   | NA                     |
| WPM         | v4.0.0, v4.0.1,v4.0.2 | v4.0.0, v4.0.1,v4.0.2 | NA  | v4.0.0, v4.0.1,v4.0.2 | NA     | NA | NA  | NA                     | NA   | NA                     |
| KBS         | v4.0.0, v4.0.1,v4.0.2 | v4.0.0, v4.0.1,v4.0.2 | NA  | NA                     | NA     | NA | NA  | NA                     | NA   | NA                     |
| TA          | v4.0.0, v4.0.1,v4.0.2 | v4.0.0                 | NA  | NA                     | NA     | NA | NA  | v4.0.0                 | NA   | NA                     |
| AA          | NA                     | NA                     | NA  | NA                     | NA     | NA | NA  | NA                     | NA   | NA                     |
| WLA         | v4.0.0, v4.0.1,v4.0.2 | v4.0.0, v4.0.1,v4.0.2 | NA  | NA                     | v4.0.0 | NA | NA  | NA                     | NA   | v4.0.0, v4.0.1,v4.0.2 |
| HVS         | v4.0.0, v4.0.1,v4.0.2 | v4.0.0                 | NA  | NA                     | v4.0.0 | NA | NA  | NA                     | NA   | NA                     |
| iHUB        | v4.0.0, v4.0.1,v4.0.2 | v4.0.0, v4.0.1,v4.0.2 | NA  | NA                     | NA     | NA | NA  | v4.0.0, v4.0.1,v4.0.2 | NA   | NA                     |
| WLS         | v4.0.0, v4.0.1,v4.0.2 | v4.0.0, v4.0.1,v4.0.2 | NA  | v4.0.0, v4.0.1,v4.0.2 | NA     | NA | NA  | NA                     | NA   | NA                     |

#### Supported upgrade path:

Binary deployment:

| Component | Abbreviation | Supports upgrade from  |
|-----------|--------------|-----------------------|
| Certificate Management Service           | CMS         |  v4.0.0, v4.0.1 |
| Authentication and Authorization Service | AAS         |  v4.0.0, v4.0.1 |
| Workload Policy Management               | WPM         |  v4.0.0, v4.0.1         |
| Key Broker Service                       | KBS         |  v4.0.0, v4.0.1 |
| Trust Agent                              | TA          |  v4.0.0, v4.0.1 |
| Application Agent                        | AA          |  v4.0.0, v4.0.1 |
| Workload Agent                           | WLA         |  v4.0.0, v4.0.1 |
| Host Verification Service                | HVS         |  v4.0.0, v4.0.1 |
| Integration Hub                          | iHUB        |  v4.0.0, v4.0.1 |
| Workload Service                         | WLS         |  v4.0.0, v4.0.1 |
| SGX Caching Service                      | SCS         |  v4.0.0, v4.0.1 |
| SGX Quote Verification Service           | SQVS        |  v4.0.0, v4.0.1 |
| SGX Host Verification Service            | SHVS        |  v4.0.0, v4.0.1 |
| SGX Agent                                | AGENT       |  v4.0.0, v4.0.1 |
| SKC Client/Library                       | SKC Library |  v4.0.0, v4.0.1 |


NOTE:
WPM does not support direct upgrade from v3.5.0 to v4.0.0. As we have changed directory structure of WPM in v3.6

For WPM, user need to upgrade to v3.6.0 first then to the latest version v4.0.0

Container deployment:

| Component | Abbreviation | Supports upgrade from  |
|-----------|--------------|-----------------------|
| Certificate Management Service           | CMS         |  v4.0.0, v4.0.1 |
| Authentication and Authorization Service | AAS         |  v4.0.0, v4.0.1 |
| Workload Policy Management               | WPM         |  v4.0.0, v4.0.1 |
| Key Broker Service                       | KBS         |  v4.0.0, v4.0.1 |
| Trust Agent                              | TA          |  v4.0.0, v4.0.1 |
| Application Agent                        | AA          |  v4.0.0, v4.0.1 |
| Workload Agent                           | WLA         |  v4.0.0, v4.0.1 |
| Host Verification Service                | HVS         |  v4.0.0, v4.0.1 |
| Integration Hub                          | iHUB        |  v4.0.0, v4.0.1 |
| Workload Service                         | WLS         |  v4.0.0, v4.0.1 |
| SGX Caching Service                      | SCS         |  v4.0.0, v4.0.1 |
| SGX Quote Verification Service           | SQVS        |  v4.0.0, v4.0.1 |
| SGX Host Verification Service            | SHVS        |  v4.0.0, v4.0.1 |
| SGX Agent                                | AGENT       |  v4.0.0, v4.0.1 |
| SKC Client/Library                       | SKC Library |  v4.0.0, v4.0.1 |

##### Upgrade to v4.0.0:
*TA and WLA* :
In v4.0.0, TA has modified policies on TPM and NVRAM and it requires to re-provision itself with HVS. This would need following 
ENV variable for the upgrade. Also, WLA would need to recreate keys as Binding Key gets updated after re-provisioning.

```shell
BEARER_TOKEN
```

NOTE:
If in case some components needs to get upgraded from v3.5.0, directly to the latest version then it would require ENV variables 
if they are mentioned above and comes in the upgrade path.
e.g if iHUB needs upgrade from v3.5.0 to v4.0.0 then it would require following ENV variables,

```shell
HVS_BASE_URL
SHVS_BASE_URL
```