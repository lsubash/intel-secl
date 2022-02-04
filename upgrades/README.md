## Upgrades of Intel<sup>®</sup> Security Libraries for Data Center (Intel<sup>®</sup> SecL-DC)

### Intel<sup>®</sup> SecL-DC started supporting upgrades from release v3.6.1

Following is the matrix of upgrade support for different components in Intel<sup>®</sup> SecL-DC

Latest release: v4.1.1

#### Compatibility Matrix:

| Component (v4) | CMS                            | AAS                            | WPM | KBS                            | TA     | AA  | WLA | HVS                            | iHUB | WLS                            |
| -------------- | ------------------------------ | ------------------------------ | --- | ------------------------------ | ------ | --- | --- | ------------------------------ | ---- | ------------------------------ |
| CMS            | NA                             | NA                             | NA  | NA                             | NA     | NA  | NA  | NA                             | NA   | NA                             |
| AAS            | v4.0.0, v4.0.1, v4.0.2, v4.1.0, v4.1.1 | NA                             | NA  | NA                             | NA     | NA  | NA  | NA                             | NA   | NA                             |
| WPM            | v4.0.0, v4.0.1, v4.0.2, v4.1.0, v4.1.1 | v4.0.0, v4.0.1, v4.0.2, v4.1.0, v4.1.1 | NA  | v4.0.0, v4.0.1, v4.0.2, v4.1.0, v4.1.1 | NA     | NA  | NA  | NA                             | NA   | NA                             |
| KBS            | v4.0.0, v4.0.1, v4.0.2, v4.1.0, v4.1.1 | v4.0.0, v4.0.1, v4.0.2, v4.1.0, v4.1.1 | NA  | NA                             | NA     | NA  | NA  | NA                             | NA   | NA                             |
| TA             | v4.0.0, v4.0.1, v4.0.2, v4.1.0, v4.1.1 | v4.0.0, v4.0.1, v4.0.2, v4.1.0, v4.1.1         | NA  | NA                             | NA     | NA  | NA  | v4.0.0, v4.0.1, v4.0.2, v4.1.0, v4.1.1         | NA   | NA                             |
| AA             | NA                             | NA                             | NA  | NA                             | NA     | NA  | NA  | NA                             | NA   | NA                             |
| WLA            | v4.0.0, v4.0.1, v4.0.2, v4.1.0, v4.1.1 | v4.0.0, v4.0.1, v4.0.2, v4.1.0, v4.1.1 | NA  | NA                             | v4.0.0 | NA  | NA  | NA                             | NA   | v4.0.0, v4.0.1, v4.0.2, v4.1.0, v4.1.1 |
| HVS            | v4.0.0, v4.0.1, v4.0.2, v4.1.0, v4.1.1 | v4.0.0, v4.0.1, v4.0.2, v4.1.0, v4.1.1                         | NA  | NA                             | v4.0.0 | NA  | NA  | NA                             | NA   | NA                             |
| iHUB           | v4.0.0, v4.0.1, v4.0.2, v4.1.0, v4.1.1 | v4.0.0, v4.0.1, v4.0.2, v4.1.0, v4.1.1 | NA  | NA                             | NA     | NA  | NA  | v4.0.0, v4.0.1, v4.0.2, v4.1.0, v4.1.1 | NA   | NA                             |
| WLS            | v4.0.0, v4.0.1, v4.0.2, v4.1.0, v4.1.1 | v4.0.0, v4.0.1, v4.0.2, v4.1.0, v4.1.1 | NA  | v4.0.0, v4.0.1, v4.0.2, v4.1.0, v4.1.1 | NA     | NA  | NA  | NA                             | NA   | NA                             |

#### Supported upgrade path:

Binary deployment:

| Component                                | Abbreviation | Supports upgrade from  |
| ---------------------------------------- | ------------ | ---------------------- |
| Certificate Management Service           | CMS          | v4.0.0, v4.0.1 |
| Authentication and Authorization Service | AAS          | v4.0.0, v4.0.1 |
| Workload Policy Management               | WPM          | v4.0.0, v4.0.1 |
| Key Broker Service                       | KBS          | v4.0.0, v4.0.1 |
| Trust Agent                              | TA           | v4.0.0, v4.0.1 |
| Application Agent                        | AA           | v4.0.0, v4.0.1 |
| Workload Agent                           | WLA          | v4.0.0, v4.0.1 |
| Host Verification Service                | HVS          | v4.0.0, v4.0.1 |
| Integration Hub                          | iHUB         | v4.0.0, v4.0.1 |
| Workload Service                         | WLS          | v4.0.0, v4.0.1 |
| SGX Caching Service                      | SCS          | v4.0.0, v4.0.1 |
| SGX Quote Verification Service           | SQVS         | v4.0.0, v4.0.1 |
| SGX Host Verification Service            | SHVS         | v4.0.0, v4.0.1 |
| SGX Agent                                | AGENT        | v4.0.0, v4.0.1 |
| SKC Client/Library                       | SKC Library  | v4.0.0, v4.0.1 |

Container deployment:

| Component                                | Abbreviation | Supports upgrade from  |
| ---------------------------------------- | ------------ | ---------------------- |
| Certificate Management Service           | CMS          | v4.0.0, v4.0.1 |
| Authentication and Authorization Service | AAS          | v4.0.0, v4.0.1 |
| Workload Policy Management               | WPM          | v4.0.0, v4.0.1 |
| Key Broker Service                       | KBS          | v4.0.0, v4.0.1 |
| Trust Agent                              | TA           | v4.0.0, v4.0.1 |
| Application Agent                        | AA           | v4.0.0, v4.0.1 |
| Workload Agent                           | WLA          | v4.0.0, v4.0.1 |
| Host Verification Service                | HVS          | v4.0.0, v4.0.1 |
| Integration Hub                          | iHUB         | v4.0.0, v4.0.1 |
| Workload Service                         | WLS          | v4.0.0, v4.0.1 |
| SGX Caching Service                      | SCS          | v4.0.0, v4.0.1 |
| SGX Quote Verification Service           | SQVS         | v4.0.0, v4.0.1 |
| SGX Host Verification Service            | SHVS         | v4.0.0, v4.0.1 |
| SGX Agent                                | AGENT        | v4.0.0, v4.0.1 |
| SKC Client/Library                       | SKC Library  | v4.0.0, v4.0.1 |

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
