## Upgrades of Intel<sup>®</sup> Security Libraries for Data Center (Intel<sup>®</sup> SecL-DC)

### Intel<sup>®</sup> SecL-DC started supporting upgrades from release v3.6.1

Following is the matrix of upgrade support for different components in Intel<sup>®</sup> SecL-DC

Latest release: v4.1.0

#### Compatibility Matrix:

| Component (v4) | CMS                            | AAS                            | WPM | KBS                            | TA     | AA  | WLA | HVS                            | iHUB | WLS                            |
| -------------- | ------------------------------ | ------------------------------ | --- | ------------------------------ | ------ | --- | --- | ------------------------------ | ---- | ------------------------------ |
| CMS            | NA                             | NA                             | NA  | NA                             | NA     | NA  | NA  | NA                             | NA   | NA                             |
| AAS            | v3.6.1, v4.0.0, v4.0.1, v4.1.0 | NA                             | NA  | NA                             | NA     | NA  | NA  | NA                             | NA   | NA                             |
| WPM            | v3.6.1, v4.0.0, v4.0.1, v4.1.0 | v3.6.1, v4.0.0, v4.0.1, v4.1.0 | NA  | v3.6.1, v4.0.0, v4.0.1, v4.1.0 | NA     | NA  | NA  | NA                             | NA   | NA                             |
| KBS            | v3.6.1, v4.0.0, v4.0.1, v4.1.0 | v3.6.1, v4.0.0, v4.0.1, v4.1.0 | NA  | NA                             | NA     | NA  | NA  | NA                             | NA   | NA                             |
| TA             | v3.6.1, v4.0.0, v4.0.1, v4.1.0 | v4.0.0, v4.0.1, v4.1.0         | NA  | NA                             | NA     | NA  | NA  | v4.0.0, v4.0.1, v4.1.0         | NA   | NA                             |
| AA             | NA                             | NA                             | NA  | NA                             | NA     | NA  | NA  | NA                             | NA   | NA                             |
| WLA            | v3.6.1, v4.0.0, v4.0.1, v4.1.0 | v3.6.1, v4.0.0, v4.0.1, v4.1.0 | NA  | NA                             | v4.0.0 | NA  | NA  | NA                             | NA   | v3.6.1, v4.0.0, v4.0.1, v4.1.0 |
| HVS            | v3.6.1, v4.0.0, v4.0.1, v4.1.0 | v4.0.0                         | NA  | NA                             | v4.0.0 | NA  | NA  | NA                             | NA   | NA                             |
| iHUB           | v3.6.1, v4.0.0, v4.0.1, v4.1.0 | v3.6.1, v4.0.0, v4.0.1, v4.1.0 | NA  | NA                             | NA     | NA  | NA  | v3.6.1, v4.0.0, v4.0.1, v4.1.0 | NA   | NA                             |
| WLS            | v3.6.1, v4.0.0, v4.0.1, v4.1.0 | v3.6.1, v4.0.0, v4.0.1, v4.1.0 | NA  | v3.6.1, v4.0.0, v4.0.1, v4.1.0 | NA     | NA  | NA  | NA                             | NA   | NA                             |

#### Supported upgrade path:

Binary deployment:

| Component                                | Abbreviation | Supports upgrade from  |
| ---------------------------------------- | ------------ | ---------------------- |
| Certificate Management Service           | CMS          | v3.6.1, v4.0.0, v4.0.1 |
| Authentication and Authorization Service | AAS          | v3.6.1, v4.0.0, v4.0.1 |
| Workload Policy Management               | WPM          | v3.6.1, v4.0.0, v4.0.1 |
| Key Broker Service                       | KBS          | v3.6.1, v4.0.0, v4.0.1 |
| Trust Agent                              | TA           | v3.6.1, v4.0.0, v4.0.1 |
| Application Agent                        | AA           | v3.6.1, v4.0.0, v4.0.1 |
| Workload Agent                           | WLA          | v3.6.1, v4.0.0, v4.0.1 |
| Host Verification Service                | HVS          | v3.6.1, v4.0.0, v4.0.1 |
| Integration Hub                          | iHUB         | v3.6.1, v4.0.0, v4.0.1 |
| Workload Service                         | WLS          | v3.6.1, v4.0.0, v4.0.1 |
| SGX Caching Service                      | SCS          | v3.6.1, v4.0.0, v4.0.1 |
| SGX Quote Verification Service           | SQVS         | v3.6.1, v4.0.0, v4.0.1 |
| SGX Host Verification Service            | SHVS         | v3.6.1, v4.0.0, v4.0.1 |
| SGX Agent                                | AGENT        | v3.6.1, v4.0.0, v4.0.1 |
| SKC Client/Library                       | SKC Library  | v3.6.1, v4.0.0, v4.0.1 |

Container deployment:

| Component                                | Abbreviation | Supports upgrade from  |
| ---------------------------------------- | ------------ | ---------------------- |
| Certificate Management Service           | CMS          | v3.6.1, v4.0.0, v4.0.1 |
| Authentication and Authorization Service | AAS          | v3.6.1, v4.0.0, v4.0.1 |
| Workload Policy Management               | WPM          | v3.6.1, v4.0.0, v4.0.1 |
| Key Broker Service                       | KBS          | v3.6.1, v4.0.0, v4.0.1 |
| Trust Agent                              | TA           | v3.6.1, v4.0.0, v4.0.1 |
| Application Agent                        | AA           | v3.6.1, v4.0.0, v4.0.1 |
| Workload Agent                           | WLA          | v3.6.1, v4.0.0, v4.0.1 |
| Host Verification Service                | HVS          | v3.6.1, v4.0.0, v4.0.1 |
| Integration Hub                          | iHUB         | v3.6.1, v4.0.0, v4.0.1 |
| Workload Service                         | WLS          | v3.6.1, v4.0.0, v4.0.1 |
| SGX Caching Service                      | SCS          | v3.6.1, v4.0.0, v4.0.1 |
| SGX Quote Verification Service           | SQVS         | v3.6.1, v4.0.0, v4.0.1 |
| SGX Host Verification Service            | SHVS         | v3.6.1, v4.0.0, v4.0.1 |
| SGX Agent                                | AGENT        | v3.6.1, v4.0.0, v4.0.1 |
| SKC Client/Library                       | SKC Library  | v3.6.1, v4.0.0, v4.0.1 |

##### Upgrade to v3.6.1:

_iHUB_ :
iHUB in v3.6.1, has added multi instance installation support. Hence, it requires following ENV variables for the upgrade,

```shell
HVS_BASE_URL
SHVS_BASE_URL
```

##### Upgrade to v4.0.0:

_TA and WLA_ :
In v4.0.0, TA has modified policies on TPM and NVRAM and it requires to re-provision itself with HVS. This would need following
ENV variable for the upgrade. Also, WLA would need to recreate keys as Binding Key gets updated after re-provisioning.

```shell
BEARER_TOKEN
```
