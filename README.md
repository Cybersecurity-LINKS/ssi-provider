## Architecture

                ssiprovider.c
                 |        |
                 |        |
          _______|        |_______
         |                        |
        vc.c                    did.c
         |                        |
         |                        |
         |                        |
    vc_internal.c           did_internal.c
                                  |
                                  |
                                  |
                                  |
                                OTT.c

- `vc.c` contains the implementation of the `VC` algorithm for the `VC_OP`
    - `vc_internal.c` contains some utility functions such as signature creation and verification and serialization and deserialization of cJSON objects.
- `did.c` contains the implementation of the `OTT` algorithm for the `DID_OP`
    - `did_internal.c` contains some utility functions to structure data in cJSON objects after CRUD operations
        - `OTT.c` allows you to write and read data on and from the Tangle 