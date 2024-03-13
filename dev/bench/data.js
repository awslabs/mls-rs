window.BENCHMARK_DATA = {
  "lastUpdate": 1710326216133,
  "repoUrl": "https://github.com/awslabs/mls-rs",
  "entries": {
    "Benchmark": [
      {
        "commit": {
          "author": {
            "email": "94983192+stefunctional@users.noreply.github.com",
            "name": "Stephane Raux",
            "username": "stefunctional"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "21b2077d930776fa74c9b86a940f36be11e67af4",
          "message": "Parallel identity validation (#910)\n\n* Benchmark adding members to a group\r\n\r\n* Validate identities in parallel\r\n\r\nResolves #501\r\n\r\n* Parallelize a couple more steps\r\n\r\nThank you Marta for the suggestions!",
          "timestamp": "2023-11-06T11:19:46-05:00",
          "tree_id": "7aadc828bc64ac24e1ff252946b41fd4fda8f301",
          "url": "https://github.com/awslabs/mls-rs/commit/21b2077d930776fa74c9b86a940f36be11e67af4"
        },
        "date": 1699309625442,
        "tool": "cargo",
        "benches": [
          {
            "name": "group_application/CipherSuite(1)/100",
            "value": 969039,
            "range": "± 66133",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000",
            "value": 974915,
            "range": "± 52492",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/10000",
            "value": 1093376,
            "range": "± 81506",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/100000",
            "value": 2249495,
            "range": "± 122430",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000000",
            "value": 14155255,
            "range": "± 720461",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/0",
            "value": 1943950,
            "range": "± 171770",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/1",
            "value": 2132747,
            "range": "± 134517",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/2",
            "value": 2376748,
            "range": "± 143023",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/0",
            "value": 1278544,
            "range": "± 100360",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/1",
            "value": 1407946,
            "range": "± 94349",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/2",
            "value": 1565476,
            "range": "± 155231",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/0",
            "value": 52236,
            "range": "± 3358",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/1",
            "value": 174128,
            "range": "± 11140",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/2",
            "value": 333051,
            "range": "± 30398",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "tomleavy@amazon.com",
            "name": "Tom Leavy",
            "username": "tomleavy"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "67c4ab2953f96a391b3bb99e905d293f4681f769",
          "message": "Add issue templates, codeowners and code of conduct (#2)\n\n* Add issue templates, codeowners and code of conduct\r\n\r\n* Update benchmark behavior",
          "timestamp": "2023-11-06T17:35:36-05:00",
          "tree_id": "7e7b9ffaf7ce5dbd9000b2e88c606c166d109f54",
          "url": "https://github.com/awslabs/mls-rs/commit/67c4ab2953f96a391b3bb99e905d293f4681f769"
        },
        "date": 1699310507064,
        "tool": "cargo",
        "benches": [
          {
            "name": "group_application/CipherSuite(1)/100",
            "value": 830442,
            "range": "± 22926",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000",
            "value": 842900,
            "range": "± 18877",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/10000",
            "value": 934333,
            "range": "± 27531",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/100000",
            "value": 1999449,
            "range": "± 16745",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000000",
            "value": 12635658,
            "range": "± 191621",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/0",
            "value": 1627339,
            "range": "± 100891",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/1",
            "value": 1806197,
            "range": "± 43939",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/2",
            "value": 2022870,
            "range": "± 47644",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/0",
            "value": 1133779,
            "range": "± 30655",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/1",
            "value": 1227539,
            "range": "± 21485",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/2",
            "value": 1350433,
            "range": "± 17514",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/0",
            "value": 44492,
            "range": "± 899",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/1",
            "value": 146189,
            "range": "± 2515",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/2",
            "value": 281753,
            "range": "± 4871",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "tomleavy@amazon.com",
            "name": "Tom Leavy",
            "username": "tomleavy"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "4e097bd8d6abe70dd021b76bd41c282918e2df52",
          "message": "Update cargo package metadata for each package (#4)\n\n* Update cargo package metadata for each package\r\n\r\n* Remove benchmarks on PR until they work\r\n\r\n* Update mls-rs-identity-x509/Cargo.toml\r\n\r\nCo-authored-by: Stephane Raux <94983192+stefunctional@users.noreply.github.com>\r\n\r\n* Remove documentation link from metadata\r\n\r\n* Update mls-rs-identity-x509/Cargo.toml\r\n\r\nCo-authored-by: Stephane Raux <94983192+stefunctional@users.noreply.github.com>\r\n\r\n---------\r\n\r\nCo-authored-by: Stephane Raux <94983192+stefunctional@users.noreply.github.com>",
          "timestamp": "2023-11-07T09:20:57+01:00",
          "tree_id": "617a81f570973c0b693dd7d0088ecc2c178265cf",
          "url": "https://github.com/awslabs/mls-rs/commit/4e097bd8d6abe70dd021b76bd41c282918e2df52"
        },
        "date": 1699345646614,
        "tool": "cargo",
        "benches": [
          {
            "name": "group_application/CipherSuite(1)/100",
            "value": 842907,
            "range": "± 39907",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000",
            "value": 861555,
            "range": "± 104633",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/10000",
            "value": 958184,
            "range": "± 40338",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/100000",
            "value": 2066939,
            "range": "± 95312",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000000",
            "value": 12938758,
            "range": "± 882664",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/0",
            "value": 1732352,
            "range": "± 159141",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/1",
            "value": 1867602,
            "range": "± 150136",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/2",
            "value": 2138383,
            "range": "± 187027",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/0",
            "value": 1208372,
            "range": "± 87147",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/1",
            "value": 1276066,
            "range": "± 138421",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/2",
            "value": 1409916,
            "range": "± 107657",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/0",
            "value": 44912,
            "range": "± 3207",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/1",
            "value": 150994,
            "range": "± 9012",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/2",
            "value": 292629,
            "range": "± 15355",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "94983192+stefunctional@users.noreply.github.com",
            "name": "Stephane Raux",
            "username": "stefunctional"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "2cb21ebb067f4f2376c6f890466f0012bdecef48",
          "message": "Remove features deemed unnecessary (#7)\n\n* Remove external_proposal feature\r\n\r\n* Remove external_commit feature\r\n\r\n* Remove all_extensions feature\r\n\r\n* Fix no_std build\r\n\r\n* Enable mls-rs-core/rfc_compliant when mls-rs/rfc_compliant is on",
          "timestamp": "2023-11-07T11:48:45-05:00",
          "tree_id": "4bf2318d3dd8a21fbd4c175ba8850ee85d839fbc",
          "url": "https://github.com/awslabs/mls-rs/commit/2cb21ebb067f4f2376c6f890466f0012bdecef48"
        },
        "date": 1699376117232,
        "tool": "cargo",
        "benches": [
          {
            "name": "group_application/CipherSuite(1)/100",
            "value": 871091,
            "range": "± 114068",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000",
            "value": 871216,
            "range": "± 42684",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/10000",
            "value": 1010576,
            "range": "± 81521",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/100000",
            "value": 2071593,
            "range": "± 159533",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000000",
            "value": 12328291,
            "range": "± 908813",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/0",
            "value": 1780674,
            "range": "± 154348",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/1",
            "value": 1927402,
            "range": "± 117957",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/2",
            "value": 2189300,
            "range": "± 156237",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/0",
            "value": 1147058,
            "range": "± 85708",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/1",
            "value": 1356628,
            "range": "± 87603",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/2",
            "value": 1357207,
            "range": "± 106202",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/0",
            "value": 43317,
            "range": "± 3419",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/1",
            "value": 149350,
            "range": "± 8944",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/2",
            "value": 319233,
            "range": "± 36265",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "103590845+mulmarta@users.noreply.github.com",
            "name": "mulmarta",
            "username": "mulmarta"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "144c7c6e32fe3aee9866c7adb6b56a99d1f4330d",
          "message": "Use rayon when generating welcome message (#9)\n\nCo-authored-by: Marta Mularczyk <mulmarta@amazon.com>",
          "timestamp": "2023-11-07T12:37:16-05:00",
          "tree_id": "223fd728ff0d6cf230679257fa6e49989b527589",
          "url": "https://github.com/awslabs/mls-rs/commit/144c7c6e32fe3aee9866c7adb6b56a99d1f4330d"
        },
        "date": 1699378983662,
        "tool": "cargo",
        "benches": [
          {
            "name": "group_application/CipherSuite(1)/100",
            "value": 703794,
            "range": "± 71800",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000",
            "value": 709925,
            "range": "± 14343",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/10000",
            "value": 793487,
            "range": "± 16671",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/100000",
            "value": 1676715,
            "range": "± 8993",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000000",
            "value": 11157064,
            "range": "± 190543",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/0",
            "value": 1378173,
            "range": "± 62981",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/1",
            "value": 1523880,
            "range": "± 30017",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/2",
            "value": 1730726,
            "range": "± 25302",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/0",
            "value": 964846,
            "range": "± 17853",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/1",
            "value": 1044440,
            "range": "± 19585",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/2",
            "value": 1148363,
            "range": "± 15807",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/0",
            "value": 37811,
            "range": "± 778",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/1",
            "value": 122609,
            "range": "± 11170",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/2",
            "value": 239478,
            "range": "± 13560",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "tomleavy@amazon.com",
            "name": "Tom Leavy",
            "username": "tomleavy"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "ca004f5919c759ce2d4fdfb8d8b130a1210a5225",
          "message": "Update docs.rs configuration and readme (#10)",
          "timestamp": "2023-11-07T14:03:46-05:00",
          "tree_id": "420542bc84c23512b098fad331f1ef37b835340d",
          "url": "https://github.com/awslabs/mls-rs/commit/ca004f5919c759ce2d4fdfb8d8b130a1210a5225"
        },
        "date": 1699384194606,
        "tool": "cargo",
        "benches": [
          {
            "name": "group_application/CipherSuite(1)/100",
            "value": 831041,
            "range": "± 16003",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000",
            "value": 844423,
            "range": "± 16433",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/10000",
            "value": 938639,
            "range": "± 23865",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/100000",
            "value": 1999693,
            "range": "± 9522",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000000",
            "value": 12705581,
            "range": "± 176167",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/0",
            "value": 1655192,
            "range": "± 84118",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/1",
            "value": 1855395,
            "range": "± 138310",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/2",
            "value": 2122974,
            "range": "± 153873",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/0",
            "value": 1178083,
            "range": "± 91590",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/1",
            "value": 1251588,
            "range": "± 107996",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/2",
            "value": 1358261,
            "range": "± 53299",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/0",
            "value": 44417,
            "range": "± 786",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/1",
            "value": 145778,
            "range": "± 2272",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/2",
            "value": 284309,
            "range": "± 5834",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "tomleavy@amazon.com",
            "name": "Tom Leavy",
            "username": "tomleavy"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "8b27972e723d769ed5f9d85791a2baa5405e84bc",
          "message": "Update versions and resolve outdated dependencies (#11)\n\n* Update versions and resolve outdated dependencies\r\n\r\n* Protoc dependency update\r\n\r\n* Fix CI issues\r\n\r\n* Reset test harness integration",
          "timestamp": "2023-11-08T09:03:10+01:00",
          "tree_id": "a07521918fb344db07d91fbc533a9d8d68acf565",
          "url": "https://github.com/awslabs/mls-rs/commit/8b27972e723d769ed5f9d85791a2baa5405e84bc"
        },
        "date": 1699430983942,
        "tool": "cargo",
        "benches": [
          {
            "name": "group_application/CipherSuite(1)/100",
            "value": 852368,
            "range": "± 13471",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000",
            "value": 858159,
            "range": "± 12502",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/10000",
            "value": 956674,
            "range": "± 16044",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/100000",
            "value": 2050446,
            "range": "± 5512",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000000",
            "value": 13652803,
            "range": "± 32095",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/0",
            "value": 1792512,
            "range": "± 88483",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/1",
            "value": 1959215,
            "range": "± 62219",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/2",
            "value": 2270052,
            "range": "± 116559",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/0",
            "value": 1200153,
            "range": "± 50614",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/1",
            "value": 1330486,
            "range": "± 57763",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/2",
            "value": 1414467,
            "range": "± 80298",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/0",
            "value": 45590,
            "range": "± 5640",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/1",
            "value": 149316,
            "range": "± 3380",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/2",
            "value": 291431,
            "range": "± 7287",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "tomleavy@amazon.com",
            "name": "Tom Leavy",
            "username": "tomleavy"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "adff439314b62f0a51b22851b8412d2b1f3c6c37",
          "message": "Update readme to fix broken badges (#13)",
          "timestamp": "2023-11-08T13:17:13-05:00",
          "tree_id": "10d0457b73497c4c2ac1312bf186a39393bf3dc3",
          "url": "https://github.com/awslabs/mls-rs/commit/adff439314b62f0a51b22851b8412d2b1f3c6c37"
        },
        "date": 1699467770497,
        "tool": "cargo",
        "benches": [
          {
            "name": "group_application/CipherSuite(1)/100",
            "value": 692973,
            "range": "± 15420",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000",
            "value": 699492,
            "range": "± 11929",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/10000",
            "value": 790255,
            "range": "± 12588",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/100000",
            "value": 1667934,
            "range": "± 9003",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000000",
            "value": 10634253,
            "range": "± 30373",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/0",
            "value": 1326688,
            "range": "± 67486",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/1",
            "value": 1481779,
            "range": "± 41441",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/2",
            "value": 1709397,
            "range": "± 29535",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/0",
            "value": 942056,
            "range": "± 5720",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/1",
            "value": 1022369,
            "range": "± 4176",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/2",
            "value": 1126382,
            "range": "± 8418",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/0",
            "value": 36712,
            "range": "± 621",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/1",
            "value": 121379,
            "range": "± 1512",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/2",
            "value": 234222,
            "range": "± 2328",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "94983192+stefunctional@users.noreply.github.com",
            "name": "Stephane Raux",
            "username": "stefunctional"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "7fa469d8375878f5f2c92ca46288a567e88e1ab4",
          "message": "Remove wildcard versions and ensure all dependencies have a version requirement (#14)\n\nIn preparation to publish to crates.io.",
          "timestamp": "2023-11-08T13:55:39-05:00",
          "tree_id": "e1ca05e1e3b6d4a9cca4d01ceb3d745bd2548070",
          "url": "https://github.com/awslabs/mls-rs/commit/7fa469d8375878f5f2c92ca46288a567e88e1ab4"
        },
        "date": 1699470075109,
        "tool": "cargo",
        "benches": [
          {
            "name": "group_application/CipherSuite(1)/100",
            "value": 689280,
            "range": "± 11999",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000",
            "value": 701953,
            "range": "± 11141",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/10000",
            "value": 781256,
            "range": "± 13915",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/100000",
            "value": 1672597,
            "range": "± 4810",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000000",
            "value": 10537963,
            "range": "± 14090",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/0",
            "value": 1318094,
            "range": "± 29412",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/1",
            "value": 1483425,
            "range": "± 22175",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/2",
            "value": 1715228,
            "range": "± 25806",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/0",
            "value": 945810,
            "range": "± 2221",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/1",
            "value": 1029246,
            "range": "± 55573",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/2",
            "value": 1122205,
            "range": "± 28408",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/0",
            "value": 37063,
            "range": "± 657",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/1",
            "value": 121323,
            "range": "± 1586",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/2",
            "value": 234515,
            "range": "± 3409",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "tomleavy@amazon.com",
            "name": "Tom Leavy",
            "username": "tomleavy"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "5d86537038e04ce4dfd745f881970d43c7dfb43a",
          "message": "Add security notice and crypto provider status to readme (#15)",
          "timestamp": "2023-11-08T14:28:49-05:00",
          "tree_id": "5033f966c127fd92add9aa642c2b9cdad4f7d341",
          "url": "https://github.com/awslabs/mls-rs/commit/5d86537038e04ce4dfd745f881970d43c7dfb43a"
        },
        "date": 1699472092816,
        "tool": "cargo",
        "benches": [
          {
            "name": "group_application/CipherSuite(1)/100",
            "value": 787400,
            "range": "± 21661",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000",
            "value": 798201,
            "range": "± 18646",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/10000",
            "value": 891206,
            "range": "± 20439",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/100000",
            "value": 1899274,
            "range": "± 17244",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000000",
            "value": 11977309,
            "range": "± 181432",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/0",
            "value": 1563737,
            "range": "± 59667",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/1",
            "value": 1761850,
            "range": "± 37954",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/2",
            "value": 1945636,
            "range": "± 54953",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/0",
            "value": 1084147,
            "range": "± 33034",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/1",
            "value": 1176084,
            "range": "± 14200",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/2",
            "value": 1287570,
            "range": "± 16867",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/0",
            "value": 42590,
            "range": "± 863",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/1",
            "value": 138820,
            "range": "± 2747",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/2",
            "value": 267606,
            "range": "± 5515",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "tomleavy@amazon.com",
            "name": "Tom Leavy",
            "username": "tomleavy"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "d0b115d2ea4754006341ba23e5910d741c6263c9",
          "message": "Fix table in readme (#16)\n\nThe markdown was incorrect in Crypto Providers and not rendering properly",
          "timestamp": "2023-11-08T14:36:09-05:00",
          "tree_id": "55a9590ce6c12a7685ecac739fa40ed3e297b4d8",
          "url": "https://github.com/awslabs/mls-rs/commit/d0b115d2ea4754006341ba23e5910d741c6263c9"
        },
        "date": 1699472542067,
        "tool": "cargo",
        "benches": [
          {
            "name": "group_application/CipherSuite(1)/100",
            "value": 843866,
            "range": "± 13892",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000",
            "value": 853736,
            "range": "± 15480",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/10000",
            "value": 950637,
            "range": "± 15901",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/100000",
            "value": 2016750,
            "range": "± 11835",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000000",
            "value": 12836311,
            "range": "± 40312",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/0",
            "value": 1627284,
            "range": "± 36476",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/1",
            "value": 1820647,
            "range": "± 55866",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/2",
            "value": 2036640,
            "range": "± 90834",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/0",
            "value": 1144341,
            "range": "± 17079",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/1",
            "value": 1243871,
            "range": "± 26733",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/2",
            "value": 1357131,
            "range": "± 33021",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/0",
            "value": 44879,
            "range": "± 1573",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/1",
            "value": 146987,
            "range": "± 2071",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/2",
            "value": 283642,
            "range": "± 5152",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "tomleavy@amazon.com",
            "name": "Tom Leavy",
            "username": "tomleavy"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "86d0cc4b9daa98a123188be594abd4a73d5b31f5",
          "message": "Remove duplicate HPKE tests and update readme (#18)",
          "timestamp": "2023-11-08T17:06:24-05:00",
          "tree_id": "a67ff5c4d4aad1ca29e60ff090282ad4b303ca49",
          "url": "https://github.com/awslabs/mls-rs/commit/86d0cc4b9daa98a123188be594abd4a73d5b31f5"
        },
        "date": 1699481551817,
        "tool": "cargo",
        "benches": [
          {
            "name": "group_application/CipherSuite(1)/100",
            "value": 835288,
            "range": "± 21182",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000",
            "value": 833711,
            "range": "± 18290",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/10000",
            "value": 946598,
            "range": "± 26319",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/100000",
            "value": 2010853,
            "range": "± 14633",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000000",
            "value": 12638471,
            "range": "± 155719",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/0",
            "value": 1636281,
            "range": "± 77431",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/1",
            "value": 1816603,
            "range": "± 46874",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/2",
            "value": 2031598,
            "range": "± 28791",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/0",
            "value": 1131976,
            "range": "± 21815",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/1",
            "value": 1234560,
            "range": "± 14214",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/2",
            "value": 1348652,
            "range": "± 23731",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/0",
            "value": 44583,
            "range": "± 1042",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/1",
            "value": 146025,
            "range": "± 2495",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/2",
            "value": 282417,
            "range": "± 12994",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "tomleavy@amazon.com",
            "name": "Tom Leavy",
            "username": "tomleavy"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "fc10a763b8897c9004977331783fda8baa904548",
          "message": "Ignore test code in coverage reports, integrate with codecov (#21)\n\n* Ignore test code in coverage reports, integrate with codecov\r\n\r\n* Add codecov to readme",
          "timestamp": "2023-11-10T14:39:26-05:00",
          "tree_id": "6e78542f10cd85f5678f499ce98fee82f5d82266",
          "url": "https://github.com/awslabs/mls-rs/commit/fc10a763b8897c9004977331783fda8baa904548"
        },
        "date": 1699645537709,
        "tool": "cargo",
        "benches": [
          {
            "name": "group_application/CipherSuite(1)/100",
            "value": 825286,
            "range": "± 20703",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000",
            "value": 825885,
            "range": "± 28917",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/10000",
            "value": 937370,
            "range": "± 18971",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/100000",
            "value": 1966847,
            "range": "± 72221",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000000",
            "value": 12669556,
            "range": "± 175688",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/0",
            "value": 1623040,
            "range": "± 75276",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/1",
            "value": 1778501,
            "range": "± 39326",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/2",
            "value": 2032405,
            "range": "± 18706",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/0",
            "value": 1139002,
            "range": "± 21048",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/1",
            "value": 1232718,
            "range": "± 28973",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/2",
            "value": 1351420,
            "range": "± 12859",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/0",
            "value": 44095,
            "range": "± 1603",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/1",
            "value": 146064,
            "range": "± 1937",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/2",
            "value": 267057,
            "range": "± 12278",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "103590845+mulmarta@users.noreply.github.com",
            "name": "mulmarta",
            "username": "mulmarta"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "e18b9c0281b13c00565aeb42917efa948bffe0a0",
          "message": "Restore HPKE tests (#23)\n\n* Restore HPKE tests\r\n\r\n* Update mls-rs-crypto-hpke/Cargo.toml\r\n\r\n---------\r\n\r\nCo-authored-by: Marta Mularczyk <mulmarta@amazon.com>",
          "timestamp": "2023-11-10T15:46:06-05:00",
          "tree_id": "c41e5baab9876296473157477ecf47c46dc0842d",
          "url": "https://github.com/awslabs/mls-rs/commit/e18b9c0281b13c00565aeb42917efa948bffe0a0"
        },
        "date": 1699649433911,
        "tool": "cargo",
        "benches": [
          {
            "name": "group_application/CipherSuite(1)/100",
            "value": 508849,
            "range": "± 4944",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000",
            "value": 518686,
            "range": "± 7436",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/10000",
            "value": 571111,
            "range": "± 27090",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/100000",
            "value": 1175374,
            "range": "± 24948",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000000",
            "value": 6898050,
            "range": "± 516642",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/0",
            "value": 1122756,
            "range": "± 43082",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/1",
            "value": 1235714,
            "range": "± 73094",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/2",
            "value": 1352251,
            "range": "± 59011",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/0",
            "value": 722986,
            "range": "± 6645",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/1",
            "value": 775254,
            "range": "± 19670",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/2",
            "value": 836677,
            "range": "± 53389",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/0",
            "value": 27607,
            "range": "± 403",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/1",
            "value": 91218,
            "range": "± 979",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/2",
            "value": 177533,
            "range": "± 1911",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "tomleavy@amazon.com",
            "name": "Tom Leavy",
            "username": "tomleavy"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "f74a5cc0db7e4ffe6c88879cd7b1ce06dd54cb75",
          "message": "Re-export AnyError and IntoAnyError from core (#29)",
          "timestamp": "2023-11-13T10:09:36-05:00",
          "tree_id": "dc0cde37fab9395def46d4633afd65a70101b297",
          "url": "https://github.com/awslabs/mls-rs/commit/f74a5cc0db7e4ffe6c88879cd7b1ce06dd54cb75"
        },
        "date": 1699888438908,
        "tool": "cargo",
        "benches": [
          {
            "name": "group_application/CipherSuite(1)/100",
            "value": 513590,
            "range": "± 7605",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000",
            "value": 518752,
            "range": "± 23809",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/10000",
            "value": 571883,
            "range": "± 38542",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/100000",
            "value": 1181608,
            "range": "± 27164",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000000",
            "value": 7751409,
            "range": "± 101709",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/0",
            "value": 1139502,
            "range": "± 132587",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/1",
            "value": 1231667,
            "range": "± 59717",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/2",
            "value": 1369670,
            "range": "± 47512",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/0",
            "value": 723646,
            "range": "± 26316",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/1",
            "value": 775361,
            "range": "± 20443",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/2",
            "value": 835646,
            "range": "± 42475",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/0",
            "value": 27873,
            "range": "± 3645",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/1",
            "value": 90248,
            "range": "± 1069",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/2",
            "value": 173423,
            "range": "± 4671",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "103590845+mulmarta@users.noreply.github.com",
            "name": "mulmarta",
            "username": "mulmarta"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "d9392bca8aa25b695d9aca4b9daed9e621567be8",
          "message": "Fix example (#22)\n\n* Fix example\r\n\r\n* Make customizable mls rules the default ones\r\n\r\n---------\r\n\r\nCo-authored-by: Marta Mularczyk <mulmarta@amazon.com>",
          "timestamp": "2023-11-13T10:58:45-05:00",
          "tree_id": "c5150146b37ad7cc95162ccd6249462993b449dc",
          "url": "https://github.com/awslabs/mls-rs/commit/d9392bca8aa25b695d9aca4b9daed9e621567be8"
        },
        "date": 1699891399007,
        "tool": "cargo",
        "benches": [
          {
            "name": "group_application/CipherSuite(1)/100",
            "value": 513950,
            "range": "± 11819",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000",
            "value": 520889,
            "range": "± 8159",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/10000",
            "value": 573498,
            "range": "± 43627",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/100000",
            "value": 1188809,
            "range": "± 28399",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000000",
            "value": 6914370,
            "range": "± 21449",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/0",
            "value": 1117869,
            "range": "± 81139",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/1",
            "value": 1282682,
            "range": "± 61038",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/2",
            "value": 1382651,
            "range": "± 63339",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/0",
            "value": 727966,
            "range": "± 14365",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/1",
            "value": 780115,
            "range": "± 4413",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/2",
            "value": 839331,
            "range": "± 9240",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/0",
            "value": 27278,
            "range": "± 1085",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/1",
            "value": 89816,
            "range": "± 2735",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/2",
            "value": 174967,
            "range": "± 15959",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "94983192+stefunctional@users.noreply.github.com",
            "name": "Stephane Raux",
            "username": "stefunctional"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "239784fc5b85bee09b1709afe19ccb6abc2980fe",
          "message": "Update update_senders when an update proposal is removed from the bundle (#31)",
          "timestamp": "2023-11-13T14:17:31-05:00",
          "tree_id": "f25236302395e3d242924bcbad3fe1256413121b",
          "url": "https://github.com/awslabs/mls-rs/commit/239784fc5b85bee09b1709afe19ccb6abc2980fe"
        },
        "date": 1699903318472,
        "tool": "cargo",
        "benches": [
          {
            "name": "group_application/CipherSuite(1)/100",
            "value": 510529,
            "range": "± 16475",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000",
            "value": 516648,
            "range": "± 8899",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/10000",
            "value": 573649,
            "range": "± 24402",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/100000",
            "value": 1176415,
            "range": "± 21208",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000000",
            "value": 6889149,
            "range": "± 27463",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/0",
            "value": 1169300,
            "range": "± 55076",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/1",
            "value": 1260805,
            "range": "± 54584",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/2",
            "value": 1378574,
            "range": "± 61291",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/0",
            "value": 723834,
            "range": "± 6896",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/1",
            "value": 775116,
            "range": "± 5192",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/2",
            "value": 835430,
            "range": "± 22480",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/0",
            "value": 27215,
            "range": "± 344",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/1",
            "value": 88801,
            "range": "± 1171",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/2",
            "value": 171603,
            "range": "± 234500",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "tomleavy@amazon.com",
            "name": "Tom Leavy",
            "username": "tomleavy"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "b309ee8d5b02c5e7db65975b2ef255c1dc9bdd3a",
          "message": "Take fuzz targets out of the main workspace (#32)\n\n* Take fuzz targets out of the main workspace\r\n\r\n* Add clippy + rust fmt",
          "timestamp": "2023-11-13T15:20:00-05:00",
          "tree_id": "e1acf9368dba307704abc899be6f2586eae2fe2d",
          "url": "https://github.com/awslabs/mls-rs/commit/b309ee8d5b02c5e7db65975b2ef255c1dc9bdd3a"
        },
        "date": 1699907070781,
        "tool": "cargo",
        "benches": [
          {
            "name": "group_application/CipherSuite(1)/100",
            "value": 512311,
            "range": "± 7037",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000",
            "value": 518267,
            "range": "± 8834",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/10000",
            "value": 573492,
            "range": "± 27799",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/100000",
            "value": 1183526,
            "range": "± 30356",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000000",
            "value": 6951021,
            "range": "± 43452",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/0",
            "value": 1121254,
            "range": "± 65485",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/1",
            "value": 1238281,
            "range": "± 57902",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/2",
            "value": 1391992,
            "range": "± 120545",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/0",
            "value": 725899,
            "range": "± 10728",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/1",
            "value": 777010,
            "range": "± 3087",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/2",
            "value": 835195,
            "range": "± 5510",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/0",
            "value": 27436,
            "range": "± 351",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/1",
            "value": 88586,
            "range": "± 780",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/2",
            "value": 171316,
            "range": "± 1838",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "tomleavy@amazon.com",
            "name": "Tom Leavy",
            "username": "tomleavy"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "fe0b2904e777dfbbf14dd5097bc0d3f8000abc06",
          "message": "[crypto-awslc] Don't use bindgen feature by default (#33)\n\n* [crypto-awslc] Don't use bindgen feature by default\r\n\r\n* Support for aws-lc on windows\r\n\r\n* Bump version",
          "timestamp": "2023-11-13T19:17:04-05:00",
          "tree_id": "afc6265c314954b5ef968e8d9ce0065dec57e0d5",
          "url": "https://github.com/awslabs/mls-rs/commit/fe0b2904e777dfbbf14dd5097bc0d3f8000abc06"
        },
        "date": 1699921289306,
        "tool": "cargo",
        "benches": [
          {
            "name": "group_application/CipherSuite(1)/100",
            "value": 509133,
            "range": "± 6751",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000",
            "value": 518794,
            "range": "± 12180",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/10000",
            "value": 573851,
            "range": "± 21305",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/100000",
            "value": 1148149,
            "range": "± 48272",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000000",
            "value": 6887571,
            "range": "± 22234",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/0",
            "value": 1127296,
            "range": "± 51191",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/1",
            "value": 1242606,
            "range": "± 49299",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/2",
            "value": 1370978,
            "range": "± 54923",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/0",
            "value": 722868,
            "range": "± 56138",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/1",
            "value": 774315,
            "range": "± 42525",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/2",
            "value": 835121,
            "range": "± 7280",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/0",
            "value": 27140,
            "range": "± 177",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/1",
            "value": 88827,
            "range": "± 1348",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/2",
            "value": 171176,
            "range": "± 6149",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "tomleavy@amazon.com",
            "name": "Tom Leavy",
            "username": "tomleavy"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "f89c4c6821362060e3e02e1d58a4c190bfef3955",
          "message": "Bump versions to prep for 0.34.2 release (#35)",
          "timestamp": "2023-11-14T11:06:47-05:00",
          "tree_id": "e790821c2e526ccbcec9204893ab27429a3daa7f",
          "url": "https://github.com/awslabs/mls-rs/commit/f89c4c6821362060e3e02e1d58a4c190bfef3955"
        },
        "date": 1699978273643,
        "tool": "cargo",
        "benches": [
          {
            "name": "group_application/CipherSuite(1)/100",
            "value": 510049,
            "range": "± 5477",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000",
            "value": 517488,
            "range": "± 5129",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/10000",
            "value": 570828,
            "range": "± 32637",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/100000",
            "value": 1174088,
            "range": "± 20236",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000000",
            "value": 7157423,
            "range": "± 17401",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/0",
            "value": 1129895,
            "range": "± 52519",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/1",
            "value": 1184989,
            "range": "± 57397",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/2",
            "value": 1335058,
            "range": "± 70105",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/0",
            "value": 720570,
            "range": "± 8240",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/1",
            "value": 774278,
            "range": "± 36308",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/2",
            "value": 832578,
            "range": "± 3831",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/0",
            "value": 26934,
            "range": "± 626",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/1",
            "value": 88103,
            "range": "± 985",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/2",
            "value": 170128,
            "range": "± 1235",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "103590845+mulmarta@users.noreply.github.com",
            "name": "mulmarta",
            "username": "mulmarta"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "51a07465ed4ce25ef5d032055b7709d8ef45ba68",
          "message": "Remove proposal check from external group (#36)\n\nCo-authored-by: Marta Mularczyk <mulmarta@amazon.com>",
          "timestamp": "2023-11-14T11:07:30-05:00",
          "tree_id": "b918d5e2a817302f1cdfd4029d468a228e28172e",
          "url": "https://github.com/awslabs/mls-rs/commit/51a07465ed4ce25ef5d032055b7709d8ef45ba68"
        },
        "date": 1699978319667,
        "tool": "cargo",
        "benches": [
          {
            "name": "group_application/CipherSuite(1)/100",
            "value": 513676,
            "range": "± 5228",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000",
            "value": 518511,
            "range": "± 6003",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/10000",
            "value": 572919,
            "range": "± 14714",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/100000",
            "value": 1180475,
            "range": "± 52433",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000000",
            "value": 7786801,
            "range": "± 24094",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/0",
            "value": 1066092,
            "range": "± 57210",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/1",
            "value": 1206121,
            "range": "± 75256",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/2",
            "value": 1358158,
            "range": "± 110086",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/0",
            "value": 722653,
            "range": "± 14885",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/1",
            "value": 775021,
            "range": "± 25593",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/2",
            "value": 836761,
            "range": "± 65941",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/0",
            "value": 27107,
            "range": "± 795",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/1",
            "value": 88915,
            "range": "± 2214",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/2",
            "value": 172000,
            "range": "± 7206",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "tomleavy@amazon.com",
            "name": "Tom Leavy",
            "username": "tomleavy"
          },
          "committer": {
            "email": "tomleavy@amazon.com",
            "name": "Tom Leavy",
            "username": "tomleavy"
          },
          "distinct": true,
          "id": "248538b95c0f9e1bb4fe5bd6607932e5b7f484d9",
          "message": "Bump version of mls-rs-core to 0.14.1",
          "timestamp": "2023-11-14T11:22:56-05:00",
          "tree_id": "e178057ab2ee5a2d4ab0a37dc5938d5cec374465",
          "url": "https://github.com/awslabs/mls-rs/commit/248538b95c0f9e1bb4fe5bd6607932e5b7f484d9"
        },
        "date": 1699979266582,
        "tool": "cargo",
        "benches": [
          {
            "name": "group_application/CipherSuite(1)/100",
            "value": 512696,
            "range": "± 7500",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000",
            "value": 517525,
            "range": "± 4012",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/10000",
            "value": 572509,
            "range": "± 11979",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/100000",
            "value": 1181394,
            "range": "± 82964",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000000",
            "value": 6863101,
            "range": "± 253410",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/0",
            "value": 1139952,
            "range": "± 47250",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/1",
            "value": 1252221,
            "range": "± 59643",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/2",
            "value": 1382886,
            "range": "± 70860",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/0",
            "value": 725694,
            "range": "± 7428",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/1",
            "value": 777369,
            "range": "± 2832",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/2",
            "value": 837493,
            "range": "± 2766",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/0",
            "value": 26985,
            "range": "± 781",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/1",
            "value": 88347,
            "range": "± 1265",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/2",
            "value": 170347,
            "range": "± 1605",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "tomleavy@amazon.com",
            "name": "Tom Leavy",
            "username": "tomleavy"
          },
          "committer": {
            "email": "tomleavy@amazon.com",
            "name": "Tom Leavy",
            "username": "tomleavy"
          },
          "distinct": true,
          "id": "a53648d90498bd653c6807a05066283e7f4a399c",
          "message": "Exclude test data from crates.io packages",
          "timestamp": "2023-11-14T11:31:38-05:00",
          "tree_id": "4f17f05da7dc4646ffcc58f453897fa322f39ed9",
          "url": "https://github.com/awslabs/mls-rs/commit/a53648d90498bd653c6807a05066283e7f4a399c"
        },
        "date": 1699979772318,
        "tool": "cargo",
        "benches": [
          {
            "name": "group_application/CipherSuite(1)/100",
            "value": 513074,
            "range": "± 7237",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000",
            "value": 519809,
            "range": "± 5052",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/10000",
            "value": 573834,
            "range": "± 34784",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/100000",
            "value": 1179235,
            "range": "± 26302",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000000",
            "value": 7247247,
            "range": "± 36041",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/0",
            "value": 1125300,
            "range": "± 106659",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/1",
            "value": 1251705,
            "range": "± 61992",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/2",
            "value": 1366585,
            "range": "± 49456",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/0",
            "value": 723157,
            "range": "± 38446",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/1",
            "value": 774200,
            "range": "± 3014",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/2",
            "value": 834349,
            "range": "± 3193",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/0",
            "value": 27818,
            "range": "± 1190",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/1",
            "value": 91182,
            "range": "± 3322",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/2",
            "value": 175616,
            "range": "± 1888",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "tomleavy@amazon.com",
            "name": "Tom Leavy",
            "username": "tomleavy"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "7240c60c6e4a482d2015a85b732c153b381222df",
          "message": "Reduce runs of interop tester in CI (#37)\n\n* Reduce runs of interop tester in CI\r\n\r\n* Remove useless output\r\n\r\n---------\r\n\r\nCo-authored-by: Marta Mularczyk <mulmarta@amazon.com>",
          "timestamp": "2023-11-14T18:16:37-05:00",
          "tree_id": "8952b76a7693f5299d223de53c393afda74403b4",
          "url": "https://github.com/awslabs/mls-rs/commit/7240c60c6e4a482d2015a85b732c153b381222df"
        },
        "date": 1700004061586,
        "tool": "cargo",
        "benches": [
          {
            "name": "group_application/CipherSuite(1)/100",
            "value": 509917,
            "range": "± 5165",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000",
            "value": 517189,
            "range": "± 12022",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/10000",
            "value": 571073,
            "range": "± 17367",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/100000",
            "value": 1177578,
            "range": "± 25109",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000000",
            "value": 7236631,
            "range": "± 28846",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/0",
            "value": 1118660,
            "range": "± 48167",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/1",
            "value": 1248536,
            "range": "± 66045",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/2",
            "value": 1340518,
            "range": "± 61095",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/0",
            "value": 725515,
            "range": "± 15209",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/1",
            "value": 780011,
            "range": "± 3143",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/2",
            "value": 839359,
            "range": "± 26587",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/0",
            "value": 27419,
            "range": "± 1340",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/1",
            "value": 89595,
            "range": "± 843",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/2",
            "value": 174841,
            "range": "± 2310",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "103590845+mulmarta@users.noreply.github.com",
            "name": "mulmarta",
            "username": "mulmarta"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "74dea2270582ad82009baff3c4f8bc3c7502d086",
          "message": "Add a WebCrypto CryptoProvider that works with Chrome (#24)\n\n* Add a WebCrypto CryptoProvider that works with Chrome\r\n\r\n* Fixup\r\n\r\n* Fixup\r\n\r\n* Remove ?Send from non-wasm build\r\n\r\n---------\r\n\r\nCo-authored-by: Marta Mularczyk <mulmarta@amazon.com>",
          "timestamp": "2023-11-14T18:17:11-05:00",
          "tree_id": "2891d38beb9a1c325bf267eab9472f7627598fba",
          "url": "https://github.com/awslabs/mls-rs/commit/74dea2270582ad82009baff3c4f8bc3c7502d086"
        },
        "date": 1700004197121,
        "tool": "cargo",
        "benches": [
          {
            "name": "group_application/CipherSuite(1)/100",
            "value": 801271,
            "range": "± 88804",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000",
            "value": 804679,
            "range": "± 42962",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/10000",
            "value": 902759,
            "range": "± 52530",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/100000",
            "value": 1873335,
            "range": "± 51447",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000000",
            "value": 11493671,
            "range": "± 529833",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/0",
            "value": 1629278,
            "range": "± 131973",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/1",
            "value": 1747209,
            "range": "± 98944",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/2",
            "value": 1915375,
            "range": "± 97940",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/0",
            "value": 1078649,
            "range": "± 73969",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/1",
            "value": 1176544,
            "range": "± 81787",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/2",
            "value": 1267715,
            "range": "± 104895",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/0",
            "value": 41788,
            "range": "± 3555",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/1",
            "value": 139664,
            "range": "± 8858",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/2",
            "value": 266003,
            "range": "± 15151",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "tomleavy@amazon.com",
            "name": "Tom Leavy",
            "username": "tomleavy"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "e32b724eac1fec43ef9ee49820b6ca25be9ea1ec",
          "message": "Use `Proposal` instead of `ProposalInfo` for unused proposals (#34)",
          "timestamp": "2023-11-14T21:27:35-05:00",
          "tree_id": "45f31793663a2edca0dbce66e9a13d86aa033108",
          "url": "https://github.com/awslabs/mls-rs/commit/e32b724eac1fec43ef9ee49820b6ca25be9ea1ec"
        },
        "date": 1700015519998,
        "tool": "cargo",
        "benches": [
          {
            "name": "group_application/CipherSuite(1)/100",
            "value": 511942,
            "range": "± 14874",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000",
            "value": 517404,
            "range": "± 7362",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/10000",
            "value": 571484,
            "range": "± 14422",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/100000",
            "value": 1177170,
            "range": "± 23668",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000000",
            "value": 7256898,
            "range": "± 43985",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/0",
            "value": 1162564,
            "range": "± 54584",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/1",
            "value": 1250015,
            "range": "± 55189",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/2",
            "value": 1381811,
            "range": "± 65584",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/0",
            "value": 723327,
            "range": "± 31004",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/1",
            "value": 774986,
            "range": "± 32752",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/2",
            "value": 835887,
            "range": "± 6561",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/0",
            "value": 27187,
            "range": "± 371",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/1",
            "value": 89130,
            "range": "± 1927",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/2",
            "value": 172315,
            "range": "± 6006",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "94983192+stefunctional@users.noreply.github.com",
            "name": "Stephane Raux",
            "username": "stefunctional"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "ff00bc48a0459fba3ebf6833fab6a50fd89e69d5",
          "message": "Conditionally compile getters for public fields (#38)\n\n* Conditionally compile getters for public fields\r\n\r\nThey only exist for FFI purposes.\r\n\r\nResolves #28\r\n\r\n* Make fields of MemberUpdate public\r\n\r\n* Fix CI",
          "timestamp": "2023-11-15T13:28:27-05:00",
          "tree_id": "dfeca71bf01659977326255e7a06e714473ab214",
          "url": "https://github.com/awslabs/mls-rs/commit/ff00bc48a0459fba3ebf6833fab6a50fd89e69d5"
        },
        "date": 1700073172440,
        "tool": "cargo",
        "benches": [
          {
            "name": "group_application/CipherSuite(1)/100",
            "value": 511497,
            "range": "± 6007",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000",
            "value": 517892,
            "range": "± 9211",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/10000",
            "value": 571518,
            "range": "± 26816",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/100000",
            "value": 1182740,
            "range": "± 26857",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000000",
            "value": 7178731,
            "range": "± 37177",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/0",
            "value": 1103537,
            "range": "± 41163",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/1",
            "value": 1202695,
            "range": "± 45012",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/2",
            "value": 1327089,
            "range": "± 46994",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/0",
            "value": 723456,
            "range": "± 80411",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/1",
            "value": 776674,
            "range": "± 3933",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/2",
            "value": 834572,
            "range": "± 12884",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/0",
            "value": 27932,
            "range": "± 281",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/1",
            "value": 91571,
            "range": "± 1790",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/2",
            "value": 177383,
            "range": "± 4334",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "103590845+mulmarta@users.noreply.github.com",
            "name": "mulmarta",
            "username": "mulmarta"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "ff20720b7f0f8dc8cfdb72579997db9129a2baca",
          "message": "Fix a decap bug for edge case trees (#39)\n\n* Fix a decap bug for edge case trees\r\n\r\n* Fixup\r\n\r\n---------\r\n\r\nCo-authored-by: Marta Mularczyk <mulmarta@amazon.com>",
          "timestamp": "2023-11-15T17:23:19-05:00",
          "tree_id": "0ae8c2deb30c338667e7833c33ca4cc41f48c7c3",
          "url": "https://github.com/awslabs/mls-rs/commit/ff20720b7f0f8dc8cfdb72579997db9129a2baca"
        },
        "date": 1700087266182,
        "tool": "cargo",
        "benches": [
          {
            "name": "group_application/CipherSuite(1)/100",
            "value": 512579,
            "range": "± 5231",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000",
            "value": 517402,
            "range": "± 10397",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/10000",
            "value": 575551,
            "range": "± 17698",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/100000",
            "value": 1189636,
            "range": "± 20159",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000000",
            "value": 7008739,
            "range": "± 136242",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/0",
            "value": 1120757,
            "range": "± 53497",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/1",
            "value": 1187920,
            "range": "± 44628",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/2",
            "value": 1344466,
            "range": "± 44532",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/0",
            "value": 725624,
            "range": "± 5307",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/1",
            "value": 777338,
            "range": "± 3775",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/2",
            "value": 840039,
            "range": "± 6505",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/0",
            "value": 27253,
            "range": "± 7191",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/1",
            "value": 90092,
            "range": "± 1049",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/2",
            "value": 175888,
            "range": "± 2923",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "mulmarta@amazon.com",
            "name": "Marta Mularczyk"
          },
          "committer": {
            "email": "mulmarta@amazon.com",
            "name": "Marta Mularczyk"
          },
          "distinct": true,
          "id": "90d34d9f4027906402ede1619758d60df1331c1d",
          "message": "Test CI changes",
          "timestamp": "2023-11-16T08:23:32+01:00",
          "tree_id": "f2663e6a164a8d75ff9f3e3b44831627235bbb9a",
          "url": "https://github.com/awslabs/mls-rs/commit/90d34d9f4027906402ede1619758d60df1331c1d"
        },
        "date": 1700119683474,
        "tool": "cargo",
        "benches": [
          {
            "name": "group_application/CipherSuite(1)/100",
            "value": 511132,
            "range": "± 4257",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000",
            "value": 518862,
            "range": "± 4048",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/10000",
            "value": 573691,
            "range": "± 30095",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/100000",
            "value": 1175159,
            "range": "± 26951",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000000",
            "value": 6844346,
            "range": "± 517156",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/0",
            "value": 1127953,
            "range": "± 76731",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/1",
            "value": 1252264,
            "range": "± 53450",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/2",
            "value": 1365311,
            "range": "± 46321",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/0",
            "value": 726911,
            "range": "± 8683",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/1",
            "value": 777115,
            "range": "± 16114",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/2",
            "value": 837584,
            "range": "± 18792",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/0",
            "value": 27248,
            "range": "± 268",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/1",
            "value": 89036,
            "range": "± 1022",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/2",
            "value": 173730,
            "range": "± 13738",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "mulmarta@amazon.com",
            "name": "Marta Mularczyk"
          },
          "committer": {
            "email": "mulmarta@amazon.com",
            "name": "Marta Mularczyk"
          },
          "distinct": true,
          "id": "0627290f6247d999ce06d8665d1cd567290181e5",
          "message": "Test CI changes",
          "timestamp": "2023-11-16T08:24:17+01:00",
          "tree_id": "8a01dfc1f4af9c4a65b89cd4b2e561c20f8e5dcc",
          "url": "https://github.com/awslabs/mls-rs/commit/0627290f6247d999ce06d8665d1cd567290181e5"
        },
        "date": 1700119722353,
        "tool": "cargo",
        "benches": [
          {
            "name": "group_application/CipherSuite(1)/100",
            "value": 514688,
            "range": "± 15024",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000",
            "value": 520521,
            "range": "± 7279",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/10000",
            "value": 573311,
            "range": "± 24025",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/100000",
            "value": 1181094,
            "range": "± 38075",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000000",
            "value": 8072113,
            "range": "± 38602",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/0",
            "value": 1118404,
            "range": "± 136757",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/1",
            "value": 1225797,
            "range": "± 35954",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/2",
            "value": 1335578,
            "range": "± 51462",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/0",
            "value": 724219,
            "range": "± 46927",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/1",
            "value": 775828,
            "range": "± 48776",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/2",
            "value": 836855,
            "range": "± 68956",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/0",
            "value": 27318,
            "range": "± 252",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/1",
            "value": 90068,
            "range": "± 15135",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/2",
            "value": 172847,
            "range": "± 3807",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "mulmarta@amazon.com",
            "name": "Marta Mularczyk"
          },
          "committer": {
            "email": "mulmarta@amazon.com",
            "name": "Marta Mularczyk"
          },
          "distinct": true,
          "id": "f378861b157e3d25097e34bc661aa326ba5b43ec",
          "message": "Test CI changes",
          "timestamp": "2023-11-16T08:28:54+01:00",
          "tree_id": "48ac743ee713fde0ecaa82ff13db0656a5b0f8fc",
          "url": "https://github.com/awslabs/mls-rs/commit/f378861b157e3d25097e34bc661aa326ba5b43ec"
        },
        "date": 1700120004569,
        "tool": "cargo",
        "benches": [
          {
            "name": "group_application/CipherSuite(1)/100",
            "value": 510426,
            "range": "± 5588",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000",
            "value": 516633,
            "range": "± 6150",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/10000",
            "value": 572199,
            "range": "± 14533",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/100000",
            "value": 1177545,
            "range": "± 81870",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000000",
            "value": 8043474,
            "range": "± 31625",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/0",
            "value": 1104945,
            "range": "± 45874",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/1",
            "value": 1235963,
            "range": "± 52406",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/2",
            "value": 1314778,
            "range": "± 59854",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/0",
            "value": 723739,
            "range": "± 74786",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/1",
            "value": 777849,
            "range": "± 8899",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/2",
            "value": 837978,
            "range": "± 4764",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/0",
            "value": 27328,
            "range": "± 304",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/1",
            "value": 89220,
            "range": "± 874",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/2",
            "value": 173193,
            "range": "± 7020",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "mulmarta@amazon.com",
            "name": "Marta Mularczyk"
          },
          "committer": {
            "email": "mulmarta@amazon.com",
            "name": "Marta Mularczyk"
          },
          "distinct": true,
          "id": "1a8b389bc8949a7f1feb92b81024186ecf0693bb",
          "message": "Test CI changes",
          "timestamp": "2023-11-16T08:31:13+01:00",
          "tree_id": "edc21471e1ff9feec1144bcfb7c2ccf3f371c077",
          "url": "https://github.com/awslabs/mls-rs/commit/1a8b389bc8949a7f1feb92b81024186ecf0693bb"
        },
        "date": 1700120140820,
        "tool": "cargo",
        "benches": [
          {
            "name": "group_application/CipherSuite(1)/100",
            "value": 511731,
            "range": "± 6675",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000",
            "value": 517763,
            "range": "± 4930",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/10000",
            "value": 573145,
            "range": "± 12362",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/100000",
            "value": 1180029,
            "range": "± 22434",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000000",
            "value": 7075224,
            "range": "± 33682",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/0",
            "value": 1146396,
            "range": "± 96802",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/1",
            "value": 1247439,
            "range": "± 55874",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/2",
            "value": 1299649,
            "range": "± 55816",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/0",
            "value": 724134,
            "range": "± 18325",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/1",
            "value": 777639,
            "range": "± 15364",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/2",
            "value": 835097,
            "range": "± 30786",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/0",
            "value": 27214,
            "range": "± 837",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/1",
            "value": 89300,
            "range": "± 853",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/2",
            "value": 172240,
            "range": "± 1696",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "mulmarta@amazon.com",
            "name": "Marta Mularczyk"
          },
          "committer": {
            "email": "mulmarta@amazon.com",
            "name": "Marta Mularczyk"
          },
          "distinct": true,
          "id": "697e8c6c9d2c3cec8551cff4afb28433dc208bdf",
          "message": "Test CI changes",
          "timestamp": "2023-11-16T08:36:06+01:00",
          "tree_id": "5b8a14b3068d9ede0b9fe10f8d0a2c7f37ce3cbb",
          "url": "https://github.com/awslabs/mls-rs/commit/697e8c6c9d2c3cec8551cff4afb28433dc208bdf"
        },
        "date": 1700120436962,
        "tool": "cargo",
        "benches": [
          {
            "name": "group_application/CipherSuite(1)/100",
            "value": 510289,
            "range": "± 20358",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000",
            "value": 519159,
            "range": "± 6328",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/10000",
            "value": 573515,
            "range": "± 21533",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/100000",
            "value": 1174808,
            "range": "± 43449",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000000",
            "value": 6874521,
            "range": "± 37188",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/0",
            "value": 1136058,
            "range": "± 50902",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/1",
            "value": 1253367,
            "range": "± 83419",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/2",
            "value": 1380170,
            "range": "± 67976",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/0",
            "value": 725141,
            "range": "± 30131",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/1",
            "value": 776216,
            "range": "± 23955",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/2",
            "value": 839480,
            "range": "± 6926",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/0",
            "value": 27373,
            "range": "± 368",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/1",
            "value": 89421,
            "range": "± 1528",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/2",
            "value": 174268,
            "range": "± 3617",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "mulmarta@amazon.com",
            "name": "Marta Mularczyk"
          },
          "committer": {
            "email": "mulmarta@amazon.com",
            "name": "Marta Mularczyk"
          },
          "distinct": true,
          "id": "4b5f8e61a961265e729e727e04f0dfb288993314",
          "message": "Revert \"Test CI changes\"\n\nThis reverts commit 697e8c6c9d2c3cec8551cff4afb28433dc208bdf.",
          "timestamp": "2023-11-16T08:38:21+01:00",
          "tree_id": "0ae8c2deb30c338667e7833c33ca4cc41f48c7c3",
          "url": "https://github.com/awslabs/mls-rs/commit/4b5f8e61a961265e729e727e04f0dfb288993314"
        },
        "date": 1700120584320,
        "tool": "cargo",
        "benches": [
          {
            "name": "group_application/CipherSuite(1)/100",
            "value": 512413,
            "range": "± 20783",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000",
            "value": 517990,
            "range": "± 7916",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/10000",
            "value": 571392,
            "range": "± 10296",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/100000",
            "value": 1178095,
            "range": "± 15632",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000000",
            "value": 7846708,
            "range": "± 35286",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/0",
            "value": 1115513,
            "range": "± 44107",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/1",
            "value": 1212401,
            "range": "± 72279",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/2",
            "value": 1338544,
            "range": "± 70208",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/0",
            "value": 723068,
            "range": "± 14119",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/1",
            "value": 776578,
            "range": "± 6703",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/2",
            "value": 834489,
            "range": "± 2364",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/0",
            "value": 27372,
            "range": "± 358",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/1",
            "value": 89223,
            "range": "± 1727",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/2",
            "value": 171819,
            "range": "± 3627",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "103590845+mulmarta@users.noreply.github.com",
            "name": "mulmarta",
            "username": "mulmarta"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "68905203fd48fe9282652bd4289975fabb428787",
          "message": "Improve interop tests CI (#41)\n\n* Improve interop tests CI\r\n\r\n* Build before running in the background\r\n\r\n* Build all flows in the foreground. Fix import bug in one feature combination\r\n\r\n* Fixup\r\n\r\n* Import fixup\r\n\r\n---------\r\n\r\nCo-authored-by: Marta Mularczyk <mulmarta@amazon.com>",
          "timestamp": "2023-11-16T09:58:35-05:00",
          "tree_id": "43fff3043ffc76a80ca0e5a8b6fd6bf8e2799e8d",
          "url": "https://github.com/awslabs/mls-rs/commit/68905203fd48fe9282652bd4289975fabb428787"
        },
        "date": 1700146985167,
        "tool": "cargo",
        "benches": [
          {
            "name": "group_application/CipherSuite(1)/100",
            "value": 511163,
            "range": "± 4927",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000",
            "value": 514840,
            "range": "± 2508",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/10000",
            "value": 570275,
            "range": "± 23853",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/100000",
            "value": 1177584,
            "range": "± 19486",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000000",
            "value": 7178433,
            "range": "± 61132",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/0",
            "value": 1098254,
            "range": "± 49804",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/1",
            "value": 1194677,
            "range": "± 46072",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/2",
            "value": 1357301,
            "range": "± 47639",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/0",
            "value": 724797,
            "range": "± 9176",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/1",
            "value": 778024,
            "range": "± 20939",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/2",
            "value": 837378,
            "range": "± 7522",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/0",
            "value": 27435,
            "range": "± 859",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/1",
            "value": 90203,
            "range": "± 1718",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/2",
            "value": 174114,
            "range": "± 1861",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "94983192+stefunctional@users.noreply.github.com",
            "name": "Stephane Raux",
            "username": "stefunctional"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "1967303af524ff5d6a9d72b0ce18486e931b42d8",
          "message": "Fix test_group_encrypt_plaintext_padding (#44)\n\nThe test started failing when the test cipher suite was changed to one\r\nthat generates signatures of variable length.\r\n\r\nResolves #43",
          "timestamp": "2023-11-16T13:08:03-05:00",
          "tree_id": "47e09571ae09b9a6d0730243c7e4f813094c3055",
          "url": "https://github.com/awslabs/mls-rs/commit/1967303af524ff5d6a9d72b0ce18486e931b42d8"
        },
        "date": 1700158364638,
        "tool": "cargo",
        "benches": [
          {
            "name": "group_application/CipherSuite(1)/100",
            "value": 513066,
            "range": "± 10069",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000",
            "value": 517740,
            "range": "± 7691",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/10000",
            "value": 572889,
            "range": "± 14122",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/100000",
            "value": 1182112,
            "range": "± 47790",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000000",
            "value": 6913372,
            "range": "± 19526",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/0",
            "value": 1111890,
            "range": "± 57805",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/1",
            "value": 1242864,
            "range": "± 69193",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/2",
            "value": 1326633,
            "range": "± 56573",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/0",
            "value": 729308,
            "range": "± 9818",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/1",
            "value": 777744,
            "range": "± 9226",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/2",
            "value": 837062,
            "range": "± 18551",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/0",
            "value": 26913,
            "range": "± 15057",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/1",
            "value": 88773,
            "range": "± 1406",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/2",
            "value": 173063,
            "range": "± 8957",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "94983192+stefunctional@users.noreply.github.com",
            "name": "Stephane Raux",
            "username": "stefunctional"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "699c2a6934a3dc80b6537c73e7283049462b63bd",
          "message": "Conditionally compile more getters (#42)\n\nFollow-up on #38",
          "timestamp": "2023-11-16T13:09:36-05:00",
          "tree_id": "aa1b8d9ded7e812f360993bc3c6946dbc07d65b3",
          "url": "https://github.com/awslabs/mls-rs/commit/699c2a6934a3dc80b6537c73e7283049462b63bd"
        },
        "date": 1700158445870,
        "tool": "cargo",
        "benches": [
          {
            "name": "group_application/CipherSuite(1)/100",
            "value": 511714,
            "range": "± 8423",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000",
            "value": 519423,
            "range": "± 7077",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/10000",
            "value": 574081,
            "range": "± 21495",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/100000",
            "value": 1176423,
            "range": "± 20967",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000000",
            "value": 7682599,
            "range": "± 35460",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/0",
            "value": 1141971,
            "range": "± 77446",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/1",
            "value": 1221454,
            "range": "± 48661",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/2",
            "value": 1368871,
            "range": "± 59368",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/0",
            "value": 724627,
            "range": "± 19820",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/1",
            "value": 775046,
            "range": "± 3946",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/2",
            "value": 835181,
            "range": "± 33118",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/0",
            "value": 27049,
            "range": "± 875",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/1",
            "value": 88608,
            "range": "± 1918",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/2",
            "value": 171317,
            "range": "± 1233",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "94983192+stefunctional@users.noreply.github.com",
            "name": "Stephane Raux",
            "username": "stefunctional"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "2f13b093f2bda5ef1613cc72a1f25b4473a7cd72",
          "message": "Make KeyPackage public (#45)",
          "timestamp": "2023-11-16T16:19:43-05:00",
          "tree_id": "3b0034c139f007cdd8373f28563c7d15a653efdc",
          "url": "https://github.com/awslabs/mls-rs/commit/2f13b093f2bda5ef1613cc72a1f25b4473a7cd72"
        },
        "date": 1700169853146,
        "tool": "cargo",
        "benches": [
          {
            "name": "group_application/CipherSuite(1)/100",
            "value": 509468,
            "range": "± 10440",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000",
            "value": 519428,
            "range": "± 20090",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/10000",
            "value": 571919,
            "range": "± 25613",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/100000",
            "value": 1180652,
            "range": "± 23716",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000000",
            "value": 6888322,
            "range": "± 46891",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/0",
            "value": 1087559,
            "range": "± 73910",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/1",
            "value": 1234097,
            "range": "± 45420",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/2",
            "value": 1322293,
            "range": "± 60563",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/0",
            "value": 724931,
            "range": "± 18472",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/1",
            "value": 774559,
            "range": "± 31348",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/2",
            "value": 834064,
            "range": "± 2952",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/0",
            "value": 26929,
            "range": "± 230",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/1",
            "value": 88833,
            "range": "± 2218",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/2",
            "value": 173343,
            "range": "± 3631",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "94983192+stefunctional@users.noreply.github.com",
            "name": "Stephane Raux",
            "username": "stefunctional"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "a226753703d101748ae0b14da3cae8d14ac1e6a1",
          "message": "Fix documentation (#46)\n\nA link was incorrect and `ProposalRef`, used in other parts of the\r\npublic API, was not exported.",
          "timestamp": "2023-11-17T10:54:26-05:00",
          "tree_id": "ebdb3cdf3dbb23c34aa7287c87b1a9a2ab9f2ef6",
          "url": "https://github.com/awslabs/mls-rs/commit/a226753703d101748ae0b14da3cae8d14ac1e6a1"
        },
        "date": 1700236740364,
        "tool": "cargo",
        "benches": [
          {
            "name": "group_application/CipherSuite(1)/100",
            "value": 513047,
            "range": "± 8589",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000",
            "value": 519473,
            "range": "± 5448",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/10000",
            "value": 574528,
            "range": "± 26476",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/100000",
            "value": 1181073,
            "range": "± 23701",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000000",
            "value": 7002788,
            "range": "± 33951",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/0",
            "value": 1088370,
            "range": "± 46813",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/1",
            "value": 1245474,
            "range": "± 47402",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/2",
            "value": 1384392,
            "range": "± 55280",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/0",
            "value": 727730,
            "range": "± 45382",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/1",
            "value": 779076,
            "range": "± 47689",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/2",
            "value": 840139,
            "range": "± 4700",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/0",
            "value": 27345,
            "range": "± 219",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/1",
            "value": 90626,
            "range": "± 1548",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/2",
            "value": 175669,
            "range": "± 2496",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "103590845+mulmarta@users.noreply.github.com",
            "name": "mulmarta",
            "username": "mulmarta"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "3c27a965892d146c11b0e3fb3bc952b801851453",
          "message": "Update interop client to the latest version (#47)\n\nCo-authored-by: Marta Mularczyk <mulmarta@amazon.com>",
          "timestamp": "2023-11-17T20:00:31+01:00",
          "tree_id": "7af219ed8f4cd3a0482776812ea239fef74bde24",
          "url": "https://github.com/awslabs/mls-rs/commit/3c27a965892d146c11b0e3fb3bc952b801851453"
        },
        "date": 1700247901242,
        "tool": "cargo",
        "benches": [
          {
            "name": "group_application/CipherSuite(1)/100",
            "value": 510285,
            "range": "± 11397",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000",
            "value": 517015,
            "range": "± 5100",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/10000",
            "value": 571230,
            "range": "± 30783",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/100000",
            "value": 1176258,
            "range": "± 26373",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000000",
            "value": 7703964,
            "range": "± 34280",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/0",
            "value": 1161230,
            "range": "± 65195",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/1",
            "value": 1241383,
            "range": "± 56833",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/2",
            "value": 1376074,
            "range": "± 58642",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/0",
            "value": 722554,
            "range": "± 26299",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/1",
            "value": 776906,
            "range": "± 34631",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/2",
            "value": 836977,
            "range": "± 24024",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/0",
            "value": 27011,
            "range": "± 1473",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/1",
            "value": 89286,
            "range": "± 2855",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/2",
            "value": 172014,
            "range": "± 231763",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "94983192+stefunctional@users.noreply.github.com",
            "name": "Stephane Raux",
            "username": "stefunctional"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "d6f9a1d5fb41d5203cda9880fb5363569c0d1411",
          "message": "Run CI on Windows (#48)\n\n* Add Windows CI\r\n\r\n* Set openssl path\r\n\r\n* attempt another ci env strategy\r\n\r\n* another attempt at env var\r\n\r\n* Install nasm (required to build aws-lc)\r\n\r\n* Install default certificates for Windows CI\r\n\r\n* Install sqlite for Windows CI\r\n\r\nSome jobs disable features, leading to not using a bundled version of\r\nsqlite and expecting to find it installed on the system.\r\n\r\n* Update aws-lc crates\r\n\r\nIt seems that it was causing multiple-definition errors when linking\r\nbecause of multiple versions of the sys crate linked together.\r\n\r\n* Use github action syntax to set env var for job step\r\n\r\nThe previous syntax doesn't work on Windows (\"Power\"shell...)\r\n\r\n* Do not set bindgen feature of aws-lc-sys as this crate already does so for platforms where it's needed\r\n\r\n---------\r\n\r\nCo-authored-by: Tom Leavy <tomleavy@amazon.com>",
          "timestamp": "2023-11-20T11:39:20-05:00",
          "tree_id": "1fc1aa83413aa3279aa5f53aa4441861d226981d",
          "url": "https://github.com/awslabs/mls-rs/commit/d6f9a1d5fb41d5203cda9880fb5363569c0d1411"
        },
        "date": 1700498629214,
        "tool": "cargo",
        "benches": [
          {
            "name": "group_application/CipherSuite(1)/100",
            "value": 511175,
            "range": "± 8337",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000",
            "value": 518047,
            "range": "± 25924",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/10000",
            "value": 570986,
            "range": "± 21067",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/100000",
            "value": 1177282,
            "range": "± 20340",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000000",
            "value": 7261545,
            "range": "± 25960",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/0",
            "value": 1108350,
            "range": "± 55243",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/1",
            "value": 1205650,
            "range": "± 57488",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/2",
            "value": 1354006,
            "range": "± 47083",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/0",
            "value": 722255,
            "range": "± 9918",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/1",
            "value": 774075,
            "range": "± 1883",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/2",
            "value": 834585,
            "range": "± 4654",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/0",
            "value": 26840,
            "range": "± 453",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/1",
            "value": 88048,
            "range": "± 1179",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/2",
            "value": 170293,
            "range": "± 1607",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "tomleavy@amazon.com",
            "name": "Tom Leavy",
            "username": "tomleavy"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "54bd2af1b9893655e5156241692b3502690b2102",
          "message": "Re-export Secret from mls_rs_core (#50)",
          "timestamp": "2023-11-20T16:10:27-05:00",
          "tree_id": "aab5b31a776e16305c41fa2ee5f39cd2c15cff45",
          "url": "https://github.com/awslabs/mls-rs/commit/54bd2af1b9893655e5156241692b3502690b2102"
        },
        "date": 1700514894946,
        "tool": "cargo",
        "benches": [
          {
            "name": "group_application/CipherSuite(1)/100",
            "value": 511721,
            "range": "± 6786",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000",
            "value": 517832,
            "range": "± 4614",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/10000",
            "value": 573723,
            "range": "± 13446",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/100000",
            "value": 1180689,
            "range": "± 27961",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000000",
            "value": 6827416,
            "range": "± 41862",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/0",
            "value": 1146537,
            "range": "± 55361",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/1",
            "value": 1201964,
            "range": "± 58906",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/2",
            "value": 1337948,
            "range": "± 121509",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/0",
            "value": 723346,
            "range": "± 19506",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/1",
            "value": 773802,
            "range": "± 5705",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/2",
            "value": 833886,
            "range": "± 3399",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/0",
            "value": 27060,
            "range": "± 429",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/1",
            "value": 88524,
            "range": "± 1172",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/2",
            "value": 172693,
            "range": "± 6837",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "tomleavy@amazon.com",
            "name": "Tom Leavy",
            "username": "tomleavy"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "ff972aea3ac7f2181c0b32596f61215869f6a5e9",
          "message": "Bump package versions for 0.35 (#49)",
          "timestamp": "2023-11-20T16:10:43-05:00",
          "tree_id": "3a93dd29e06eb9d0c184a8f329061ee9237d2eb8",
          "url": "https://github.com/awslabs/mls-rs/commit/ff972aea3ac7f2181c0b32596f61215869f6a5e9"
        },
        "date": 1700514912369,
        "tool": "cargo",
        "benches": [
          {
            "name": "group_application/CipherSuite(1)/100",
            "value": 513828,
            "range": "± 14656",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000",
            "value": 521048,
            "range": "± 7304",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/10000",
            "value": 575318,
            "range": "± 24533",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/100000",
            "value": 1180811,
            "range": "± 28982",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000000",
            "value": 7340194,
            "range": "± 39906",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/0",
            "value": 1108085,
            "range": "± 59789",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/1",
            "value": 1207643,
            "range": "± 49923",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/2",
            "value": 1320474,
            "range": "± 51211",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/0",
            "value": 723888,
            "range": "± 36428",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/1",
            "value": 775202,
            "range": "± 31591",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/2",
            "value": 837801,
            "range": "± 67612",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/0",
            "value": 27070,
            "range": "± 274",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/1",
            "value": 88834,
            "range": "± 1345",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/2",
            "value": 171582,
            "range": "± 2661",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "tomleavy@amazon.com",
            "name": "Tom Leavy",
            "username": "tomleavy"
          },
          "committer": {
            "email": "tomleavy@amazon.com",
            "name": "Tom Leavy",
            "username": "tomleavy"
          },
          "distinct": true,
          "id": "56c584828fe42ec620b4e6cdb3bf95c368a1fe9e",
          "message": "Add crates.io description for mls-rs-crypto-webcrypto",
          "timestamp": "2023-11-20T16:19:32-05:00",
          "tree_id": "05a585ad790c8ad328b10bfba74d73d8d04843d8",
          "url": "https://github.com/awslabs/mls-rs/commit/56c584828fe42ec620b4e6cdb3bf95c368a1fe9e"
        },
        "date": 1700515444370,
        "tool": "cargo",
        "benches": [
          {
            "name": "group_application/CipherSuite(1)/100",
            "value": 510290,
            "range": "± 12229",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000",
            "value": 519883,
            "range": "± 25975",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/10000",
            "value": 574028,
            "range": "± 38341",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/100000",
            "value": 1185346,
            "range": "± 73415",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000000",
            "value": 6891341,
            "range": "± 197680",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/0",
            "value": 1122896,
            "range": "± 62338",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/1",
            "value": 1266519,
            "range": "± 52687",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/2",
            "value": 1394723,
            "range": "± 61421",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/0",
            "value": 726859,
            "range": "± 4790",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/1",
            "value": 777664,
            "range": "± 4772",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/2",
            "value": 838401,
            "range": "± 46522",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/0",
            "value": 27187,
            "range": "± 7178",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/1",
            "value": 88515,
            "range": "± 816",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/2",
            "value": 171325,
            "range": "± 8427",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "103590845+mulmarta@users.noreply.github.com",
            "name": "mulmarta",
            "username": "mulmarta"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "cc0ff86c018ad22825f0d4cfd04e735b8bc25342",
          "message": "Add context to identity functions (#52)",
          "timestamp": "2023-12-05T18:47:33-05:00",
          "tree_id": "60fe591c5fa3256e2ea8b41d0a12fefd7f819779",
          "url": "https://github.com/awslabs/mls-rs/commit/cc0ff86c018ad22825f0d4cfd04e735b8bc25342"
        },
        "date": 1701820317095,
        "tool": "cargo",
        "benches": [
          {
            "name": "group_application/CipherSuite(1)/100",
            "value": 511154,
            "range": "± 5059",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000",
            "value": 517768,
            "range": "± 4264",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/10000",
            "value": 572204,
            "range": "± 31636",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/100000",
            "value": 1175840,
            "range": "± 29602",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000000",
            "value": 7788536,
            "range": "± 50143",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/0",
            "value": 1119792,
            "range": "± 145904",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/1",
            "value": 1206798,
            "range": "± 46215",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/2",
            "value": 1332621,
            "range": "± 44699",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/0",
            "value": 725072,
            "range": "± 86998",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/1",
            "value": 776730,
            "range": "± 6963",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/2",
            "value": 837383,
            "range": "± 29726",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/0",
            "value": 27358,
            "range": "± 150",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/1",
            "value": 89722,
            "range": "± 744",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/2",
            "value": 173603,
            "range": "± 944",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "tomleavy@amazon.com",
            "name": "Tom Leavy",
            "username": "tomleavy"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "b53a2574f25e2ef5691b949a980e52b18ba2f9c3",
          "message": "Remove outdated identity warning API (#51)",
          "timestamp": "2023-12-05T18:47:54-05:00",
          "tree_id": "122937f79a0fd4f19e7b2a6cfeae896bd8f81f3c",
          "url": "https://github.com/awslabs/mls-rs/commit/b53a2574f25e2ef5691b949a980e52b18ba2f9c3"
        },
        "date": 1701820342606,
        "tool": "cargo",
        "benches": [
          {
            "name": "group_application/CipherSuite(1)/100",
            "value": 512646,
            "range": "± 10975",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000",
            "value": 520355,
            "range": "± 10142",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/10000",
            "value": 574507,
            "range": "± 14470",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/100000",
            "value": 1182295,
            "range": "± 29685",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000000",
            "value": 7265772,
            "range": "± 74310",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/0",
            "value": 1159893,
            "range": "± 74702",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/1",
            "value": 1242609,
            "range": "± 53410",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/2",
            "value": 1348167,
            "range": "± 65266",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/0",
            "value": 723796,
            "range": "± 22504",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/1",
            "value": 776829,
            "range": "± 5358",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/2",
            "value": 834421,
            "range": "± 2964",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/0",
            "value": 26983,
            "range": "± 6735",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/1",
            "value": 88711,
            "range": "± 3425",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/2",
            "value": 171942,
            "range": "± 1297",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "103590845+mulmarta@users.noreply.github.com",
            "name": "mulmarta",
            "username": "mulmarta"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "064495c80bf3cd1fde1e519ad474fc485396adb3",
          "message": "Update dependencies (#53)\n\nCo-authored-by: Marta Mularczyk <mulmarta@amazon.com>",
          "timestamp": "2023-12-07T10:05:17-05:00",
          "tree_id": "f0a1f63fe2542db9ebf25b8d4c1ee64599b343ae",
          "url": "https://github.com/awslabs/mls-rs/commit/064495c80bf3cd1fde1e519ad474fc485396adb3"
        },
        "date": 1701961784994,
        "tool": "cargo",
        "benches": [
          {
            "name": "group_application/CipherSuite(1)/100",
            "value": 510982,
            "range": "± 2575",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000",
            "value": 519660,
            "range": "± 6778",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/10000",
            "value": 573091,
            "range": "± 26234",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/100000",
            "value": 1177080,
            "range": "± 19792",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000000",
            "value": 6936957,
            "range": "± 53522",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/0",
            "value": 1137192,
            "range": "± 49471",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/1",
            "value": 1191674,
            "range": "± 35690",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/2",
            "value": 1298334,
            "range": "± 47534",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/0",
            "value": 727042,
            "range": "± 4136",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/1",
            "value": 778166,
            "range": "± 5197",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/2",
            "value": 839041,
            "range": "± 3597",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/0",
            "value": 26752,
            "range": "± 502",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/1",
            "value": 87993,
            "range": "± 14683",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/2",
            "value": 170185,
            "range": "± 3653",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "103590845+mulmarta@users.noreply.github.com",
            "name": "mulmarta",
            "username": "mulmarta"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "881f3217e97882a10c72c5fcb734cbb5b1a3e5a1",
          "message": "Expose tree hash (#54)\n\n* Expose tree hash\r\n\r\n* Update mls-rs/src/external_client/group.rs\r\n\r\nCo-authored-by: Stephane Raux <94983192+stefunctional@users.noreply.github.com>\r\n\r\n---------\r\n\r\nCo-authored-by: Marta Mularczyk <mulmarta@amazon.com>\r\nCo-authored-by: Stephane Raux <94983192+stefunctional@users.noreply.github.com>",
          "timestamp": "2023-12-07T10:05:37-05:00",
          "tree_id": "d8e1632c1b6b3c406d36fd1189c69dc202950966",
          "url": "https://github.com/awslabs/mls-rs/commit/881f3217e97882a10c72c5fcb734cbb5b1a3e5a1"
        },
        "date": 1701961811335,
        "tool": "cargo",
        "benches": [
          {
            "name": "group_application/CipherSuite(1)/100",
            "value": 514845,
            "range": "± 8543",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000",
            "value": 522483,
            "range": "± 7270",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/10000",
            "value": 574646,
            "range": "± 32970",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/100000",
            "value": 1191040,
            "range": "± 26462",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000000",
            "value": 6995952,
            "range": "± 108251",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/0",
            "value": 1083010,
            "range": "± 60410",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/1",
            "value": 1268492,
            "range": "± 70960",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/2",
            "value": 1373367,
            "range": "± 57993",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/0",
            "value": 726319,
            "range": "± 59356",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/1",
            "value": 777644,
            "range": "± 22799",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/2",
            "value": 842300,
            "range": "± 6015",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/0",
            "value": 27210,
            "range": "± 524",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/1",
            "value": 89592,
            "range": "± 1749",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/2",
            "value": 176091,
            "range": "± 4284",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "94983192+stefunctional@users.noreply.github.com",
            "name": "Stephane Raux",
            "username": "stefunctional"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "dcc0df39cea46a3a634b1bcafdf979e1848cd01f",
          "message": "Implement serialization for strings (#55)\n\n* Implement serialization for strings\r\n\r\n* Bump versions",
          "timestamp": "2023-12-14T15:55:14-05:00",
          "tree_id": "d83bec0456316f8228525cac7017e6030906ea51",
          "url": "https://github.com/awslabs/mls-rs/commit/dcc0df39cea46a3a634b1bcafdf979e1848cd01f"
        },
        "date": 1702587573896,
        "tool": "cargo",
        "benches": [
          {
            "name": "group_application/CipherSuite(1)/100",
            "value": 508959,
            "range": "± 21704",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000",
            "value": 515128,
            "range": "± 5812",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/10000",
            "value": 571404,
            "range": "± 18056",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/100000",
            "value": 1174745,
            "range": "± 22456",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000000",
            "value": 6927726,
            "range": "± 17732",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/0",
            "value": 1129866,
            "range": "± 79038",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/1",
            "value": 1219941,
            "range": "± 49675",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/2",
            "value": 1351894,
            "range": "± 60356",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/0",
            "value": 725521,
            "range": "± 40789",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/1",
            "value": 775859,
            "range": "± 55454",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/2",
            "value": 836136,
            "range": "± 6027",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/0",
            "value": 27989,
            "range": "± 751",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/1",
            "value": 92814,
            "range": "± 1117",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/2",
            "value": 179149,
            "range": "± 1542",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "103590845+mulmarta@users.noreply.github.com",
            "name": "mulmarta",
            "username": "mulmarta"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "742c9463b15d7cb37ff9ba6e539e06eab44d0008",
          "message": "Expose more group info (#56)\n\nCo-authored-by: Marta Mularczyk <mulmarta@amazon.com>",
          "timestamp": "2023-12-19T11:04:13-05:00",
          "tree_id": "164b8f566df8a318926a94bb0591859ef75cf1a1",
          "url": "https://github.com/awslabs/mls-rs/commit/742c9463b15d7cb37ff9ba6e539e06eab44d0008"
        },
        "date": 1703002122090,
        "tool": "cargo",
        "benches": [
          {
            "name": "group_application/CipherSuite(1)/100",
            "value": 512858,
            "range": "± 12514",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000",
            "value": 517939,
            "range": "± 10261",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/10000",
            "value": 570978,
            "range": "± 23316",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/100000",
            "value": 1168285,
            "range": "± 25159",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000000",
            "value": 7649153,
            "range": "± 35154",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/0",
            "value": 1155915,
            "range": "± 56638",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/1",
            "value": 1215560,
            "range": "± 54156",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/2",
            "value": 1412523,
            "range": "± 46033",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/0",
            "value": 726945,
            "range": "± 30368",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/1",
            "value": 777222,
            "range": "± 3490",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/2",
            "value": 837301,
            "range": "± 30949",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/0",
            "value": 27597,
            "range": "± 482",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/1",
            "value": 90506,
            "range": "± 1342",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/2",
            "value": 175808,
            "range": "± 3898",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "103590845+mulmarta@users.noreply.github.com",
            "name": "mulmarta",
            "username": "mulmarta"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "e46b4790b9b39a3dc68fea8b4259d85de9151f68",
          "message": "Add tests and fixes for external commit proposal rules (#59)\n\n* Add tests and fixes for external commit proposal rules\r\n\r\n* Apply suggestions from code review\r\n\r\nCo-authored-by: Stephane Raux <94983192+stefunctional@users.noreply.github.com>\r\n\r\n* Fixup\r\n\r\n---------\r\n\r\nCo-authored-by: Marta Mularczyk <mulmarta@amazon.com>\r\nCo-authored-by: Stephane Raux <94983192+stefunctional@users.noreply.github.com>",
          "timestamp": "2024-01-05T15:54:43-05:00",
          "tree_id": "cd3548ef9f4d35af1096f77f94302f05e6ef9991",
          "url": "https://github.com/awslabs/mls-rs/commit/e46b4790b9b39a3dc68fea8b4259d85de9151f68"
        },
        "date": 1704488349179,
        "tool": "cargo",
        "benches": [
          {
            "name": "group_application/CipherSuite(1)/100",
            "value": 512284,
            "range": "± 5413",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000",
            "value": 518255,
            "range": "± 5574",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/10000",
            "value": 573386,
            "range": "± 21107",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/100000",
            "value": 1176690,
            "range": "± 32452",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000000",
            "value": 6870303,
            "range": "± 36265",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/0",
            "value": 1091840,
            "range": "± 48184",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/1",
            "value": 1221663,
            "range": "± 38632",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/2",
            "value": 1318706,
            "range": "± 50915",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/0",
            "value": 721824,
            "range": "± 4204",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/1",
            "value": 773406,
            "range": "± 4048",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/2",
            "value": 834107,
            "range": "± 4998",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/0",
            "value": 25266,
            "range": "± 499",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/1",
            "value": 83073,
            "range": "± 1079",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/2",
            "value": 162584,
            "range": "± 1518",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "tomleavy@amazon.com",
            "name": "Tom Leavy",
            "username": "tomleavy"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "8f2b391258bcf5fd7041f037c3c57ed86ab0d30a",
          "message": "Introduce `ExportedTree` to represent ratchet tree contents (#58)\n\n* Introduce ExportedTree to represent ratchet tree contents\r\n\r\n* Rework based on `Cow` to avoid unnecessary cloning of the tree\r\n\r\n* Fix build\r\n\r\n* Apply suggestions from code review\r\n\r\nCo-authored-by: Stephane Raux <94983192+stefunctional@users.noreply.github.com>\r\n\r\n* fix clippy\r\n\r\n---------\r\n\r\nCo-authored-by: Marta Mularczyk <mulmarta@amazon.com>\r\nCo-authored-by: Stephane Raux <94983192+stefunctional@users.noreply.github.com>",
          "timestamp": "2024-01-05T16:47:07-05:00",
          "tree_id": "b870410b1ea59279936912196fada3cc5b5b53bc",
          "url": "https://github.com/awslabs/mls-rs/commit/8f2b391258bcf5fd7041f037c3c57ed86ab0d30a"
        },
        "date": 1704491489803,
        "tool": "cargo",
        "benches": [
          {
            "name": "group_application/CipherSuite(1)/100",
            "value": 509501,
            "range": "± 14905",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000",
            "value": 514177,
            "range": "± 6923",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/10000",
            "value": 568663,
            "range": "± 28280",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/100000",
            "value": 1174391,
            "range": "± 12602",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000000",
            "value": 7046591,
            "range": "± 26736",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/0",
            "value": 1080303,
            "range": "± 117322",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/1",
            "value": 1195513,
            "range": "± 52138",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/2",
            "value": 1303820,
            "range": "± 44797",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/0",
            "value": 719665,
            "range": "± 62276",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/1",
            "value": 769958,
            "range": "± 2498",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/2",
            "value": 830826,
            "range": "± 3245",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/0",
            "value": 25301,
            "range": "± 590",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/1",
            "value": 83018,
            "range": "± 1080",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/2",
            "value": 160721,
            "range": "± 24166",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "tomleavy@amazon.com",
            "name": "Tom Leavy",
            "username": "tomleavy"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "e8d573c3e6424a8fc36898da84d5da3d26f18615",
          "message": "Commit option for generating an external commit group info (#61)\n\n* Commit option for generating an external commit group info\r\n\r\n* Fixup\r\n\r\n---------\r\n\r\nCo-authored-by: Marta Mularczyk <mulmarta@amazon.com>",
          "timestamp": "2024-01-09T15:44:21+01:00",
          "tree_id": "a6d8c8b85d48156345f2aae71f85a2d22cc9abaf",
          "url": "https://github.com/awslabs/mls-rs/commit/e8d573c3e6424a8fc36898da84d5da3d26f18615"
        },
        "date": 1704811726524,
        "tool": "cargo",
        "benches": [
          {
            "name": "group_application/CipherSuite(1)/100",
            "value": 512184,
            "range": "± 19546",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000",
            "value": 518535,
            "range": "± 3017",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/10000",
            "value": 574863,
            "range": "± 20543",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/100000",
            "value": 1184098,
            "range": "± 24805",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000000",
            "value": 7243427,
            "range": "± 297394",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/0",
            "value": 1152710,
            "range": "± 54378",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/1",
            "value": 1226705,
            "range": "± 48990",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/2",
            "value": 1346921,
            "range": "± 45937",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/0",
            "value": 721543,
            "range": "± 3783",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/1",
            "value": 771810,
            "range": "± 3905",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/2",
            "value": 832329,
            "range": "± 6037",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/0",
            "value": 25344,
            "range": "± 523",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/1",
            "value": 83132,
            "range": "± 938",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/2",
            "value": 161014,
            "range": "± 1985",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "martin@geisler.net",
            "name": "Martin Geisler",
            "username": "mgeisler"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "c6dcba96b2051e07388d1da98a430c776eb774a7",
          "message": "Remove unused dependencies (#62)",
          "timestamp": "2024-01-15T09:12:54-05:00",
          "tree_id": "a3a241000e2f6f4a84d0e757e818e917b9f20985",
          "url": "https://github.com/awslabs/mls-rs/commit/c6dcba96b2051e07388d1da98a430c776eb774a7"
        },
        "date": 1705328234793,
        "tool": "cargo",
        "benches": [
          {
            "name": "group_application/CipherSuite(1)/100",
            "value": 510515,
            "range": "± 12838",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000",
            "value": 514551,
            "range": "± 19732",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/10000",
            "value": 569873,
            "range": "± 26930",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/100000",
            "value": 1179743,
            "range": "± 25861",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000000",
            "value": 7363050,
            "range": "± 24882",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/0",
            "value": 1114220,
            "range": "± 53090",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/1",
            "value": 1237479,
            "range": "± 62810",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/2",
            "value": 1381271,
            "range": "± 66242",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/0",
            "value": 722188,
            "range": "± 41383",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/1",
            "value": 771496,
            "range": "± 12428",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/2",
            "value": 831459,
            "range": "± 3951",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/0",
            "value": 25256,
            "range": "± 657",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/1",
            "value": 83253,
            "range": "± 3507",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/2",
            "value": 161240,
            "range": "± 33100",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "103590845+mulmarta@users.noreply.github.com",
            "name": "mulmarta",
            "username": "mulmarta"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "eb985351ec8b4f61941779f997bedf83b4366a7b",
          "message": "Expose a function to compute `ProposalRef` from a proposal `MlsMessage` (#60)",
          "timestamp": "2024-01-15T09:13:25-05:00",
          "tree_id": "2e329df195723cc076ccb26ad50b86c3c83f8294",
          "url": "https://github.com/awslabs/mls-rs/commit/eb985351ec8b4f61941779f997bedf83b4366a7b"
        },
        "date": 1705328267021,
        "tool": "cargo",
        "benches": [
          {
            "name": "group_application/CipherSuite(1)/100",
            "value": 511232,
            "range": "± 7782",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000",
            "value": 518814,
            "range": "± 6219",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/10000",
            "value": 574602,
            "range": "± 24700",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/100000",
            "value": 1185309,
            "range": "± 20055",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000000",
            "value": 7242531,
            "range": "± 473653",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/0",
            "value": 1122669,
            "range": "± 99578",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/1",
            "value": 1172587,
            "range": "± 46589",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/2",
            "value": 1375407,
            "range": "± 60495",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/0",
            "value": 723866,
            "range": "± 31452",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/1",
            "value": 774411,
            "range": "± 22284",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/2",
            "value": 834483,
            "range": "± 5854",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/0",
            "value": 25098,
            "range": "± 1045",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/1",
            "value": 82372,
            "range": "± 1488",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/2",
            "value": 162560,
            "range": "± 7932",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "94983192+stefunctional@users.noreply.github.com",
            "name": "Stephane Raux",
            "username": "stefunctional"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "a17d9b5d08e8804d502f7c1078820492e8218e88",
          "message": "Expose content type of encrypted messages to external group (#63)",
          "timestamp": "2024-01-15T09:13:39-05:00",
          "tree_id": "fdd9e9598c464f10ebd846af0fd8fc346798434c",
          "url": "https://github.com/awslabs/mls-rs/commit/a17d9b5d08e8804d502f7c1078820492e8218e88"
        },
        "date": 1705328278302,
        "tool": "cargo",
        "benches": [
          {
            "name": "group_application/CipherSuite(1)/100",
            "value": 510611,
            "range": "± 9611",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000",
            "value": 518111,
            "range": "± 10326",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/10000",
            "value": 572404,
            "range": "± 25403",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/100000",
            "value": 1186334,
            "range": "± 91934",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000000",
            "value": 6892842,
            "range": "± 37162",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/0",
            "value": 1096270,
            "range": "± 65695",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/1",
            "value": 1201016,
            "range": "± 66573",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/2",
            "value": 1303749,
            "range": "± 42732",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/0",
            "value": 719448,
            "range": "± 14218",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/1",
            "value": 771618,
            "range": "± 17496",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/2",
            "value": 831353,
            "range": "± 6210",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/0",
            "value": 25573,
            "range": "± 196",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/1",
            "value": 84769,
            "range": "± 1142",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/2",
            "value": 163825,
            "range": "± 2507",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "103590845+mulmarta@users.noreply.github.com",
            "name": "mulmarta",
            "username": "mulmarta"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "f0ae87b07b864fc9316a4bfc227dca72fd2ee406",
          "message": "Add API for clearing proposal cache (#64)\n\nCo-authored-by: Marta Mularczyk <mulmarta@amazon.com>",
          "timestamp": "2024-01-16T16:10:18-05:00",
          "tree_id": "ecc3b668283d1eee2b8266f8a112f66371066115",
          "url": "https://github.com/awslabs/mls-rs/commit/f0ae87b07b864fc9316a4bfc227dca72fd2ee406"
        },
        "date": 1705439670351,
        "tool": "cargo",
        "benches": [
          {
            "name": "group_application/CipherSuite(1)/100",
            "value": 511135,
            "range": "± 5547",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000",
            "value": 514344,
            "range": "± 9016",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/10000",
            "value": 568857,
            "range": "± 12073",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/100000",
            "value": 1180565,
            "range": "± 78386",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000000",
            "value": 6923375,
            "range": "± 181456",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/0",
            "value": 1101665,
            "range": "± 61970",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/1",
            "value": 1207591,
            "range": "± 44623",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/2",
            "value": 1318131,
            "range": "± 50629",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/0",
            "value": 719557,
            "range": "± 17137",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/1",
            "value": 769284,
            "range": "± 8002",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/2",
            "value": 830947,
            "range": "± 5082",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/0",
            "value": 25226,
            "range": "± 735",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/1",
            "value": 82628,
            "range": "± 837",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/2",
            "value": 160339,
            "range": "± 1427",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "94983192+stefunctional@users.noreply.github.com",
            "name": "Stephane Raux",
            "username": "stefunctional"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "468ffc50b740b540c5a840979b943d964ccdc7c7",
          "message": "Depend on portable-atomic-* only if the target has no OS (#65)",
          "timestamp": "2024-01-17T12:23:05+01:00",
          "tree_id": "13440b528676da32df5ccbc96db946f4a883ce4e",
          "url": "https://github.com/awslabs/mls-rs/commit/468ffc50b740b540c5a840979b943d964ccdc7c7"
        },
        "date": 1705490839692,
        "tool": "cargo",
        "benches": [
          {
            "name": "group_application/CipherSuite(1)/100",
            "value": 511079,
            "range": "± 12601",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000",
            "value": 517450,
            "range": "± 10414",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/10000",
            "value": 572157,
            "range": "± 18652",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/100000",
            "value": 1179006,
            "range": "± 21411",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000000",
            "value": 6873833,
            "range": "± 149873",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/0",
            "value": 1136453,
            "range": "± 71183",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/1",
            "value": 1199239,
            "range": "± 53278",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/2",
            "value": 1318086,
            "range": "± 65969",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/0",
            "value": 721142,
            "range": "± 11644",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/1",
            "value": 773550,
            "range": "± 6151",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/2",
            "value": 831148,
            "range": "± 9144",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/0",
            "value": 25410,
            "range": "± 530",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/1",
            "value": 83065,
            "range": "± 962",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/2",
            "value": 161450,
            "range": "± 7417",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "tomleavy@amazon.com",
            "name": "Tom Leavy",
            "username": "tomleavy"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "405119f200ecc27917d18648d6cac5188cedc073",
          "message": "Add unused proposals to `CommitOutput` (#67)\n\n* Add unused proposals to CommitOutput\r\n\r\n* Fix ProposalInfo specialization\r\n\r\n- The specialization macro needs to be invoked after the impl block, so\r\n  that macros generated for this block are available at the\r\n  specialization point.\r\n- Macro qualification is not supported in the crate where the macro is\r\n  defined.\r\n\r\n---------\r\n\r\nCo-authored-by: Stephane Raux <sraux@amazon.com>",
          "timestamp": "2024-01-19T15:27:09+01:00",
          "tree_id": "1ea1e31236416e4048ab41261649c9e6fe75a7ab",
          "url": "https://github.com/awslabs/mls-rs/commit/405119f200ecc27917d18648d6cac5188cedc073"
        },
        "date": 1705674689142,
        "tool": "cargo",
        "benches": [
          {
            "name": "group_application/CipherSuite(1)/100",
            "value": 510719,
            "range": "± 14715",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000",
            "value": 516938,
            "range": "± 13048",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/10000",
            "value": 570812,
            "range": "± 4416",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/100000",
            "value": 1179161,
            "range": "± 18179",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000000",
            "value": 7361736,
            "range": "± 21287",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/0",
            "value": 1086778,
            "range": "± 54734",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/1",
            "value": 1183812,
            "range": "± 40537",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/2",
            "value": 1314834,
            "range": "± 42673",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/0",
            "value": 726815,
            "range": "± 70339",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/1",
            "value": 775948,
            "range": "± 24497",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/2",
            "value": 836832,
            "range": "± 4326",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/0",
            "value": 25484,
            "range": "± 336",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/1",
            "value": 83402,
            "range": "± 28842",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/2",
            "value": 162002,
            "range": "± 1426",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "94983192+stefunctional@users.noreply.github.com",
            "name": "Stephane Raux",
            "username": "stefunctional"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "bd74f0ccab420c724a7ef25222adcc52a6ac2916",
          "message": "Use atomic in core when available (#66)\n\nThis is the\r\n[recommended](https://doc.rust-lang.org/alloc/sync/index.html) way to\r\ncheck for atomic support in core.",
          "timestamp": "2024-01-19T11:03:29-05:00",
          "tree_id": "004c3d9717f3de3ee252e35a5be4fc8fd31d9d69",
          "url": "https://github.com/awslabs/mls-rs/commit/bd74f0ccab420c724a7ef25222adcc52a6ac2916"
        },
        "date": 1705680466652,
        "tool": "cargo",
        "benches": [
          {
            "name": "group_application/CipherSuite(1)/100",
            "value": 511225,
            "range": "± 5787",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000",
            "value": 517882,
            "range": "± 5988",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/10000",
            "value": 571982,
            "range": "± 16921",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/100000",
            "value": 1166719,
            "range": "± 22104",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000000",
            "value": 6973560,
            "range": "± 23429",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/0",
            "value": 1097009,
            "range": "± 49910",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/1",
            "value": 1197994,
            "range": "± 36047",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/2",
            "value": 1353495,
            "range": "± 36194",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/0",
            "value": 723409,
            "range": "± 9058",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/1",
            "value": 772092,
            "range": "± 4833",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/2",
            "value": 833497,
            "range": "± 5762",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/0",
            "value": 25465,
            "range": "± 284",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/1",
            "value": 83940,
            "range": "± 1587",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/2",
            "value": 161793,
            "range": "± 7549",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "tomleavy@amazon.com",
            "name": "Tom Leavy",
            "username": "tomleavy"
          },
          "committer": {
            "email": "tomleavy@amazon.com",
            "name": "Tom Leavy",
            "username": "tomleavy"
          },
          "distinct": true,
          "id": "dda97ff0a9b7d6dac1f678b72db4476a41e81ce9",
          "message": "Bump version to 0.37.1",
          "timestamp": "2024-01-19T11:20:22-05:00",
          "tree_id": "d51cc96a2f4eeb6394b6dbeaaf269aa667e4bbd3",
          "url": "https://github.com/awslabs/mls-rs/commit/dda97ff0a9b7d6dac1f678b72db4476a41e81ce9"
        },
        "date": 1705681511578,
        "tool": "cargo",
        "benches": [
          {
            "name": "group_application/CipherSuite(1)/100",
            "value": 510636,
            "range": "± 8757",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000",
            "value": 517292,
            "range": "± 29494",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/10000",
            "value": 571202,
            "range": "± 7876",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/100000",
            "value": 1180453,
            "range": "± 25713",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000000",
            "value": 6935183,
            "range": "± 36348",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/0",
            "value": 1098726,
            "range": "± 40845",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/1",
            "value": 1183541,
            "range": "± 38881",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/2",
            "value": 1318826,
            "range": "± 39393",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/0",
            "value": 718960,
            "range": "± 6162",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/1",
            "value": 769068,
            "range": "± 3647",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/2",
            "value": 828867,
            "range": "± 31590",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/0",
            "value": 25175,
            "range": "± 375",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/1",
            "value": 82866,
            "range": "± 795",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/2",
            "value": 160602,
            "range": "± 1563",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "94983192+stefunctional@users.noreply.github.com",
            "name": "Stephane Raux",
            "username": "stefunctional"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "d9d9e2eafd5b4a17ac86b1ca4a449595512cc652",
          "message": "Fix conditional compilation of proposal references (#68)\n\n* Fix conditional compilation of proposal references\r\n\r\nSome uses were incorrectly guarded by the `external_client` feature.\r\n\r\n* Do not exclude fuzz target when running cargo-hack\r\n\r\nThe fuzz target is not a member of the workspace, which triggers a\r\nwarning.\r\n\r\n* Make ProposalMessageDescription non_exhaustive",
          "timestamp": "2024-01-23T15:11:36-05:00",
          "tree_id": "10e758ae744c3fd2ff63685ea2452056ca1c17c2",
          "url": "https://github.com/awslabs/mls-rs/commit/d9d9e2eafd5b4a17ac86b1ca4a449595512cc652"
        },
        "date": 1706040953957,
        "tool": "cargo",
        "benches": [
          {
            "name": "group_application/CipherSuite(1)/100",
            "value": 510088,
            "range": "± 17984",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000",
            "value": 519960,
            "range": "± 17703",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/10000",
            "value": 582993,
            "range": "± 23704",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/100000",
            "value": 1181116,
            "range": "± 47434",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000000",
            "value": 6858551,
            "range": "± 61504",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/0",
            "value": 1136405,
            "range": "± 67696",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/1",
            "value": 1209701,
            "range": "± 43433",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/2",
            "value": 1327692,
            "range": "± 47191",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/0",
            "value": 721977,
            "range": "± 10914",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/1",
            "value": 774360,
            "range": "± 5464",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/2",
            "value": 835714,
            "range": "± 7957",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/0",
            "value": 25510,
            "range": "± 9024",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/1",
            "value": 84150,
            "range": "± 3497",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/2",
            "value": 164190,
            "range": "± 8290",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "94983192+stefunctional@users.noreply.github.com",
            "name": "Stephane Raux",
            "username": "stefunctional"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "3c57e91bbf7db544fece950d1ca569a7788efda4",
          "message": "Fix unused proposals when receiving commit (#69)\n\n* Test that rejected proposals are proposals in cache and not in commit when receiving commit\r\n\r\nThe test currently fails and the implementation will be fixed in the\r\nnext commit.\r\n\r\n* Fix unused proposals when receiving commit\r\n\r\nUnused proposals were previously made of the proposals in the received\r\ncommit that would cause the commit to be invalid and thus were excluded.\r\nBut given that invalid proposals when receiving a commit cause the\r\nentire commit to be rejected, it means that unused proposals were always\r\nempty when receiving a commit.\r\n\r\nUnused proposals are now made of the proposals in the receiver's cache\r\nthat are not in the received commit.\r\n\r\n* Rename rejected_proposals to unused_proposals\r\n\r\nThe previous term was confusing in the context of receiving a commit.\r\n\r\nThis also removes outdated comments in tests from back when only unused\r\nproposals from the committer were returned.",
          "timestamp": "2024-01-25T13:25:16-05:00",
          "tree_id": "6db4cf3f33368ecc094407ba620ece406de6d32d",
          "url": "https://github.com/awslabs/mls-rs/commit/3c57e91bbf7db544fece950d1ca569a7788efda4"
        },
        "date": 1706207371814,
        "tool": "cargo",
        "benches": [
          {
            "name": "group_application/CipherSuite(1)/100",
            "value": 511735,
            "range": "± 20186",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000",
            "value": 516910,
            "range": "± 16302",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/10000",
            "value": 575759,
            "range": "± 24200",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/100000",
            "value": 1148212,
            "range": "± 27129",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000000",
            "value": 7102048,
            "range": "± 113744",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/0",
            "value": 1160131,
            "range": "± 69294",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/1",
            "value": 1251505,
            "range": "± 55358",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/2",
            "value": 1369250,
            "range": "± 58302",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/0",
            "value": 722914,
            "range": "± 85078",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/1",
            "value": 772187,
            "range": "± 27425",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/2",
            "value": 831955,
            "range": "± 4368",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/0",
            "value": 25261,
            "range": "± 309",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/1",
            "value": 83358,
            "range": "± 812",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/2",
            "value": 161136,
            "range": "± 7926",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "103590845+mulmarta@users.noreply.github.com",
            "name": "mulmarta",
            "username": "mulmarta"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "da44ac672a7290989f418a5a120a2a92516fccd6",
          "message": "Fix cipher suite choice in aws-lc crypto provider (#70)\n\nCo-authored-by: Marta Mularczyk <mulmarta@amazon.com>",
          "timestamp": "2024-01-29T10:14:39-05:00",
          "tree_id": "61d49bfd6e05be5f5e4ad22b66e0864c304b552a",
          "url": "https://github.com/awslabs/mls-rs/commit/da44ac672a7290989f418a5a120a2a92516fccd6"
        },
        "date": 1706541541577,
        "tool": "cargo",
        "benches": [
          {
            "name": "group_application/CipherSuite(1)/100",
            "value": 516453,
            "range": "± 32964",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000",
            "value": 520726,
            "range": "± 5430",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/10000",
            "value": 575444,
            "range": "± 34951",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/100000",
            "value": 1180931,
            "range": "± 80856",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000000",
            "value": 6918119,
            "range": "± 43545",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/0",
            "value": 1110743,
            "range": "± 137935",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/1",
            "value": 1229470,
            "range": "± 76656",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/2",
            "value": 1345089,
            "range": "± 41898",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/0",
            "value": 725738,
            "range": "± 8010",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/1",
            "value": 776227,
            "range": "± 34573",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/2",
            "value": 839249,
            "range": "± 7970",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/0",
            "value": 25701,
            "range": "± 1731",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/1",
            "value": 84958,
            "range": "± 1689",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/2",
            "value": 165349,
            "range": "± 23736",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "94983192+stefunctional@users.noreply.github.com",
            "name": "Stephane Raux",
            "username": "stefunctional"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "bed6f60d97ab052a3558b27bbee6d40e4728f388",
          "message": "Update aws-lc-sys (#71)\n\naws-lc-rs released a minor update bringing in a major update of a sys\r\ncrate, causing 2 sys crates to be linked together (since we depend\r\ndirectly on this sys crate too), leading to duplicate symbol errors.",
          "timestamp": "2024-01-29T11:31:37-05:00",
          "tree_id": "90ae0c3afa936d342a021ab3b8c2c3d6af59c34e",
          "url": "https://github.com/awslabs/mls-rs/commit/bed6f60d97ab052a3558b27bbee6d40e4728f388"
        },
        "date": 1706546170733,
        "tool": "cargo",
        "benches": [
          {
            "name": "group_application/CipherSuite(1)/100",
            "value": 502921,
            "range": "± 8575",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000",
            "value": 512077,
            "range": "± 2516",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/10000",
            "value": 564054,
            "range": "± 16223",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/100000",
            "value": 1173007,
            "range": "± 33021",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000000",
            "value": 7225921,
            "range": "± 53195",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/0",
            "value": 1134417,
            "range": "± 44379",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/1",
            "value": 1230502,
            "range": "± 55674",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/2",
            "value": 1348526,
            "range": "± 51242",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/0",
            "value": 714051,
            "range": "± 20922",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/1",
            "value": 766909,
            "range": "± 4679",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/2",
            "value": 829278,
            "range": "± 11745",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/0",
            "value": 25612,
            "range": "± 705",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/1",
            "value": 83902,
            "range": "± 1576",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/2",
            "value": 163017,
            "range": "± 3288",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "103590845+mulmarta@users.noreply.github.com",
            "name": "mulmarta",
            "username": "mulmarta"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "c3bea80ea2511ea4b29ad7e274e2e89ba656c02c",
          "message": "Allow validating messages (#72)\n\n* Allow validating messages\r\n\r\n* Add a key package validation method to ExternalClient\r\n\r\n---------\r\n\r\nCo-authored-by: Marta Mularczyk <mulmarta@amazon.com>",
          "timestamp": "2024-01-29T12:24:16-05:00",
          "tree_id": "6dea9721221a3576813ab1adfe604dc14bf9b873",
          "url": "https://github.com/awslabs/mls-rs/commit/c3bea80ea2511ea4b29ad7e274e2e89ba656c02c"
        },
        "date": 1706549307523,
        "tool": "cargo",
        "benches": [
          {
            "name": "group_application/CipherSuite(1)/100",
            "value": 510570,
            "range": "± 4775",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000",
            "value": 516895,
            "range": "± 19326",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/10000",
            "value": 572716,
            "range": "± 4639",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/100000",
            "value": 1171344,
            "range": "± 103683",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000000",
            "value": 7156107,
            "range": "± 38580",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/0",
            "value": 1123298,
            "range": "± 48479",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/1",
            "value": 1209834,
            "range": "± 54096",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/2",
            "value": 1343886,
            "range": "± 39493",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/0",
            "value": 721251,
            "range": "± 11972",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/1",
            "value": 772893,
            "range": "± 5876",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/2",
            "value": 833186,
            "range": "± 2353",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/0",
            "value": 25379,
            "range": "± 336",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/1",
            "value": 83365,
            "range": "± 1090",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/2",
            "value": 162044,
            "range": "± 1751",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "tomleavy@amazon.com",
            "name": "Tom Leavy",
            "username": "tomleavy"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "105faf3f0a4270ef4381d82fe0f88f1d396e67e1",
          "message": "Bump versions for 0.37.2 release (#73)",
          "timestamp": "2024-01-29T14:53:07-05:00",
          "tree_id": "00332a9ceff88d3a371f2bc6b7b3f8fc4f3f919e",
          "url": "https://github.com/awslabs/mls-rs/commit/105faf3f0a4270ef4381d82fe0f88f1d396e67e1"
        },
        "date": 1706558245620,
        "tool": "cargo",
        "benches": [
          {
            "name": "group_application/CipherSuite(1)/100",
            "value": 511008,
            "range": "± 17590",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000",
            "value": 517166,
            "range": "± 11205",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/10000",
            "value": 570580,
            "range": "± 13790",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/100000",
            "value": 1178197,
            "range": "± 32903",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000000",
            "value": 7434085,
            "range": "± 30666",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/0",
            "value": 1140398,
            "range": "± 51747",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/1",
            "value": 1179473,
            "range": "± 79071",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/2",
            "value": 1339316,
            "range": "± 51479",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/0",
            "value": 720464,
            "range": "± 20279",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/1",
            "value": 773566,
            "range": "± 15062",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/2",
            "value": 830892,
            "range": "± 2159",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/0",
            "value": 25479,
            "range": "± 218",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/1",
            "value": 84159,
            "range": "± 24026",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/2",
            "value": 164270,
            "range": "± 12565",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "103590845+mulmarta@users.noreply.github.com",
            "name": "mulmarta",
            "username": "mulmarta"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "606bfa389104b0dbd616d0d3373864071862514c",
          "message": "Make secret tree work with arbitrary indices (#74)\n\n* Make secret tree work with arbitrary indices, not only usize\r\n\r\n* Fixup\r\n\r\n* Fixup\r\n\r\n* Fixup\r\n\r\n* Fixup\r\n\r\n* Update mls-rs/src/group/secret_tree.rs\r\n\r\nCo-authored-by: Stephane Raux <94983192+stefunctional@users.noreply.github.com>\r\n\r\n* Replace BTreeMap by Vec\r\n\r\n* Fixup\r\n\r\n* Fixup\r\n\r\n---------\r\n\r\nCo-authored-by: Marta Mularczyk <mulmarta@amazon.com>\r\nCo-authored-by: Stephane Raux <94983192+stefunctional@users.noreply.github.com>",
          "timestamp": "2024-02-06T12:16:43+01:00",
          "tree_id": "f53a6289a0474cabdea83f7d6cb2167fa2a4ded5",
          "url": "https://github.com/awslabs/mls-rs/commit/606bfa389104b0dbd616d0d3373864071862514c"
        },
        "date": 1707218461811,
        "tool": "cargo",
        "benches": [
          {
            "name": "group_application/CipherSuite(1)/100",
            "value": 497734,
            "range": "± 8488",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000",
            "value": 512194,
            "range": "± 18696",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/10000",
            "value": 565741,
            "range": "± 7241",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/100000",
            "value": 1175448,
            "range": "± 31112",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000000",
            "value": 6850994,
            "range": "± 25529",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/0",
            "value": 1063519,
            "range": "± 74074",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/1",
            "value": 1209894,
            "range": "± 40728",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/2",
            "value": 1292899,
            "range": "± 47345",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/0",
            "value": 714739,
            "range": "± 16800",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/1",
            "value": 761449,
            "range": "± 5946",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/2",
            "value": 817793,
            "range": "± 4634",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/0",
            "value": 23567,
            "range": "± 185",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/1",
            "value": 76021,
            "range": "± 3805",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/2",
            "value": 144846,
            "range": "± 2474",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "103590845+mulmarta@users.noreply.github.com",
            "name": "mulmarta",
            "username": "mulmarta"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "6fa5e72ee2ec909bbca4a9f8769513edb03e41f1",
          "message": "Apply pending commits automatically when processing that commit (#75)\n\n* Add possibility to receive own commit as MlsMessage\r\n\r\n* Fixup\r\n\r\n* Fixup\r\n\r\n---------\r\n\r\nCo-authored-by: Marta Mularczyk <mulmarta@amazon.com>",
          "timestamp": "2024-02-06T11:48:47-05:00",
          "tree_id": "f629947f98651511401ffc777f962cb2f375b5c4",
          "url": "https://github.com/awslabs/mls-rs/commit/6fa5e72ee2ec909bbca4a9f8769513edb03e41f1"
        },
        "date": 1707238386597,
        "tool": "cargo",
        "benches": [
          {
            "name": "group_application/CipherSuite(1)/100",
            "value": 502261,
            "range": "± 10224",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000",
            "value": 508620,
            "range": "± 9461",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/10000",
            "value": 563247,
            "range": "± 45878",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/100000",
            "value": 1174786,
            "range": "± 35062",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000000",
            "value": 7183604,
            "range": "± 18850",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/0",
            "value": 1112159,
            "range": "± 66852",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/1",
            "value": 1222359,
            "range": "± 51581",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/2",
            "value": 1343889,
            "range": "± 47025",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/0",
            "value": 714134,
            "range": "± 18132",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/1",
            "value": 762267,
            "range": "± 8718",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/2",
            "value": 818699,
            "range": "± 2695",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/0",
            "value": 23517,
            "range": "± 219",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/1",
            "value": 75972,
            "range": "± 1144",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/2",
            "value": 145666,
            "range": "± 1432",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "103590845+mulmarta@users.noreply.github.com",
            "name": "mulmarta",
            "username": "mulmarta"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "fe24123f80d4b5b8027e75e8688ca3e56743b553",
          "message": "Add a serde feature and derive serde for most structs used by providers (#76)\n\n\r\n---------\r\n\r\nCo-authored-by: Marta Mularczyk <mulmarta@amazon.com>\r\nCo-authored-by: Stephane Raux <94983192+stefunctional@users.noreply.github.com>",
          "timestamp": "2024-02-13T15:11:08-05:00",
          "tree_id": "f45e149ebd75918567a4ff54a191da1bf6e55f4d",
          "url": "https://github.com/awslabs/mls-rs/commit/fe24123f80d4b5b8027e75e8688ca3e56743b553"
        },
        "date": 1707855333321,
        "tool": "cargo",
        "benches": [
          {
            "name": "group_application/CipherSuite(1)/100",
            "value": 538957,
            "range": "± 18850",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000",
            "value": 515452,
            "range": "± 17396",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/10000",
            "value": 571460,
            "range": "± 15650",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/100000",
            "value": 1188443,
            "range": "± 38965",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000000",
            "value": 6871964,
            "range": "± 49115",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/0",
            "value": 1114214,
            "range": "± 87501",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/1",
            "value": 1204350,
            "range": "± 53815",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/2",
            "value": 1317604,
            "range": "± 41571",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/0",
            "value": 724668,
            "range": "± 10911",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/1",
            "value": 769174,
            "range": "± 20655",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/2",
            "value": 825292,
            "range": "± 9962",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/0",
            "value": 23517,
            "range": "± 399",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/1",
            "value": 76058,
            "range": "± 875",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/2",
            "value": 145093,
            "range": "± 1769",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "103590845+mulmarta@users.noreply.github.com",
            "name": "mulmarta",
            "username": "mulmarta"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "91fd6474646f781d86f18b92d393162477aa3ae4",
          "message": "Add customization example (#79)\n\n* Add customization example\r\n\r\n* Fixup\r\n\r\n* Update mls-rs/examples/custom.rs\r\n\r\nCo-authored-by: Stephane Raux <94983192+stefunctional@users.noreply.github.com>\r\n\r\n---------\r\n\r\nCo-authored-by: Marta Mularczyk <mulmarta@amazon.com>\r\nCo-authored-by: Stephane Raux <94983192+stefunctional@users.noreply.github.com>",
          "timestamp": "2024-02-16T10:38:50-05:00",
          "tree_id": "d695f545060145ef10f9ec2a30d103e6cb572613",
          "url": "https://github.com/awslabs/mls-rs/commit/91fd6474646f781d86f18b92d393162477aa3ae4"
        },
        "date": 1708098197661,
        "tool": "cargo",
        "benches": [
          {
            "name": "group_application/CipherSuite(1)/100",
            "value": 507322,
            "range": "± 13930",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000",
            "value": 512469,
            "range": "± 27755",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/10000",
            "value": 567079,
            "range": "± 6066",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/100000",
            "value": 1173582,
            "range": "± 19564",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000000",
            "value": 6960548,
            "range": "± 38254",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/0",
            "value": 1129749,
            "range": "± 48902",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/1",
            "value": 1202382,
            "range": "± 57126",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/2",
            "value": 1349866,
            "range": "± 46735",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/0",
            "value": 716784,
            "range": "± 40731",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/1",
            "value": 764252,
            "range": "± 5353",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/2",
            "value": 818303,
            "range": "± 29026",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/0",
            "value": 23732,
            "range": "± 242",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/1",
            "value": 76682,
            "range": "± 1483",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/2",
            "value": 146235,
            "range": "± 1034",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "103590845+mulmarta@users.noreply.github.com",
            "name": "mulmarta",
            "username": "mulmarta"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "cdc826f0b5ebef27ad73e31ea6449ea7c3e32a39",
          "message": "Async build (#80)\n\n* Make the sqlite provider compile in the async mode. Make webcrypto not compile for archs other than wasm32\r\n\r\n* Remove redundant imports pointed out by nightly clippy\r\n\r\n---------\r\n\r\nCo-authored-by: Marta Mularczyk <mulmarta@amazon.com>",
          "timestamp": "2024-02-21T16:08:06+01:00",
          "tree_id": "e7261a9b2fe9c61042c307fa98fa0031537fe76d",
          "url": "https://github.com/awslabs/mls-rs/commit/cdc826f0b5ebef27ad73e31ea6449ea7c3e32a39"
        },
        "date": 1708528357198,
        "tool": "cargo",
        "benches": [
          {
            "name": "group_application/CipherSuite(1)/100",
            "value": 508279,
            "range": "± 17406",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000",
            "value": 515468,
            "range": "± 16937",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/10000",
            "value": 579332,
            "range": "± 16955",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/100000",
            "value": 1182699,
            "range": "± 39961",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000000",
            "value": 7008030,
            "range": "± 68357",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/0",
            "value": 1136738,
            "range": "± 61945",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/1",
            "value": 1251440,
            "range": "± 46537",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/2",
            "value": 1340430,
            "range": "± 38750",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/0",
            "value": 718395,
            "range": "± 6217",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/1",
            "value": 764768,
            "range": "± 3172",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/2",
            "value": 821312,
            "range": "± 3896",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/0",
            "value": 23506,
            "range": "± 229",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/1",
            "value": 76125,
            "range": "± 1227",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/2",
            "value": 145234,
            "range": "± 2754",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "mgeisler@google.com",
            "name": "Martin Geisler",
            "username": "mgeisler"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "811047649aa67c86a6345bee82a837d2a5f49472",
          "message": "Introduce mls-rs-uniffi (#82)\n\n* Bump maybe-async to 0.2.10\r\n\r\nThis version contains https://github.com/fMeow/maybe-async-rs/pull/24,\r\nwhich should make it possible to combine UniFFI and maybe-async.\r\n\r\n* Introduce mls-rs-uniffi\r\n\r\nThis new create is a thin wrapper around mls-rs which exposes a subset\r\nof it’s interface using a [UniFFI-compatible][1] API.\r\n\r\nWe will expand this over the next few weeks to be a full API usable by\r\nmessaging apps on different platforms.\r\n\r\n[1]: https://mozilla.github.io/uniffi-rs/",
          "timestamp": "2024-02-23T10:09:44-05:00",
          "tree_id": "8845affb078ad114e806f70ac72c9dfe7628f5be",
          "url": "https://github.com/awslabs/mls-rs/commit/811047649aa67c86a6345bee82a837d2a5f49472"
        },
        "date": 1708701251569,
        "tool": "cargo",
        "benches": [
          {
            "name": "group_application/CipherSuite(1)/100",
            "value": 544900,
            "range": "± 16219",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000",
            "value": 551896,
            "range": "± 15344",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/10000",
            "value": 607410,
            "range": "± 15559",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/100000",
            "value": 1199615,
            "range": "± 22188",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000000",
            "value": 7173087,
            "range": "± 68344",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/0",
            "value": 1100036,
            "range": "± 61578",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/1",
            "value": 1221437,
            "range": "± 52441",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/2",
            "value": 1363143,
            "range": "± 50834",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/0",
            "value": 727055,
            "range": "± 10193",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/1",
            "value": 775935,
            "range": "± 10826",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/2",
            "value": 837902,
            "range": "± 12934",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/0",
            "value": 23863,
            "range": "± 482",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/1",
            "value": 76553,
            "range": "± 1384",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/2",
            "value": 147013,
            "range": "± 2417",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "94983192+stefunctional@users.noreply.github.com",
            "name": "Stephane Raux",
            "username": "stefunctional"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "13eba2c6874e24c9afc6bc56273e0d0d37fcb602",
          "message": "Customize debug output of byte arrays (#83)\n\nThis should help reduce the noise when troubleshooting issues and\r\ndebug-printing values.\r\n\r\nBy default byte arrays are written with their length only, unless the\r\nalternate debug format is requested (`\"{:#?}\"`), in which case the bytes\r\nare also written in hex format. Group IDs should usually be short and\r\ntheir bytes are always written.",
          "timestamp": "2024-02-23T10:11:27-05:00",
          "tree_id": "e43efa28eb8b7b032d9e98f7c8ce70a7efbcaf36",
          "url": "https://github.com/awslabs/mls-rs/commit/13eba2c6874e24c9afc6bc56273e0d0d37fcb602"
        },
        "date": 1708701350275,
        "tool": "cargo",
        "benches": [
          {
            "name": "group_application/CipherSuite(1)/100",
            "value": 514001,
            "range": "± 17824",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000",
            "value": 516410,
            "range": "± 13588",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/10000",
            "value": 576884,
            "range": "± 17763",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/100000",
            "value": 1182558,
            "range": "± 20690",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000000",
            "value": 7375653,
            "range": "± 23192",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/0",
            "value": 1113254,
            "range": "± 76915",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/1",
            "value": 1195960,
            "range": "± 52211",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/2",
            "value": 1330853,
            "range": "± 56176",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/0",
            "value": 720769,
            "range": "± 22910",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/1",
            "value": 765852,
            "range": "± 4251",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/2",
            "value": 822014,
            "range": "± 21180",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/0",
            "value": 23794,
            "range": "± 230",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/1",
            "value": 76741,
            "range": "± 1228",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/2",
            "value": 145993,
            "range": "± 1578",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "103590845+mulmarta@users.noreply.github.com",
            "name": "mulmarta",
            "username": "mulmarta"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "fd946722d77e83bf11d3356f7e4a267727b90b52",
          "message": "Don't take ownership for messages where not necessary (#84)\n\n* Take welcome message by reference\r\n\r\n* Take group info by reference\r\n\r\n* Take ciphertext by reference\r\n\r\n* Fixup\r\n\r\n* Fixup\r\n\r\n* Simplify tests\r\n\r\n* Fixup\r\n\r\n---------\r\n\r\nCo-authored-by: Marta Mularczyk <mulmarta@amazon.com>",
          "timestamp": "2024-02-26T10:30:17-05:00",
          "tree_id": "ef1730090e911c69e8574ad74efa4c4983c2f549",
          "url": "https://github.com/awslabs/mls-rs/commit/fd946722d77e83bf11d3356f7e4a267727b90b52"
        },
        "date": 1708961679323,
        "tool": "cargo",
        "benches": [
          {
            "name": "group_application/CipherSuite(1)/100",
            "value": 521799,
            "range": "± 16755",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000",
            "value": 515064,
            "range": "± 18340",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/10000",
            "value": 606661,
            "range": "± 25381",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/100000",
            "value": 1145158,
            "range": "± 26316",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000000",
            "value": 6859219,
            "range": "± 62692",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/0",
            "value": 1143538,
            "range": "± 65631",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/1",
            "value": 1234139,
            "range": "± 38899",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/2",
            "value": 1350461,
            "range": "± 41066",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/0",
            "value": 719570,
            "range": "± 32397",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/1",
            "value": 765208,
            "range": "± 22012",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/2",
            "value": 819475,
            "range": "± 4522",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/0",
            "value": 23638,
            "range": "± 243",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/1",
            "value": 76891,
            "range": "± 993",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/2",
            "value": 146103,
            "range": "± 1441",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "martin@geisler.net",
            "name": "Martin Geisler",
            "username": "mgeisler"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "d34b971314199fc73cee5a5fb830bc6a732fb629",
          "message": "Execute UniFFI bindings via a simple Python test (#87)\n\nThis uses the UniFFI test helpers to make the `libmls_rs_uniffi.so`\r\nfile available to the Python script.\r\n\r\nI would have liked to use `$CARGO_TARGET_TMPDIR` to place the\r\ntemporary files in a stable place under `target/`, but this variable\r\nis only set for integration tests, not unit tests. So the script now\r\nends up somewhere in your system temp directory.\r\n\r\nWe could decide to only use integration tests for these tests, let me\r\nknow what you think!\r\n\r\nThe test is very simple here: it simply executes the Python script,\r\nwhich then has to return with a zero exit code. If it fails, the\r\noutput is printed and you then have to debug the Python code by hand.\r\n\r\nRelated to #81.",
          "timestamp": "2024-02-26T17:38:42+01:00",
          "tree_id": "43bafa9353b83266448bf7410634103d49c5cb75",
          "url": "https://github.com/awslabs/mls-rs/commit/d34b971314199fc73cee5a5fb830bc6a732fb629"
        },
        "date": 1708965780417,
        "tool": "cargo",
        "benches": [
          {
            "name": "group_application/CipherSuite(1)/100",
            "value": 509850,
            "range": "± 13417",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000",
            "value": 517551,
            "range": "± 17560",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/10000",
            "value": 592751,
            "range": "± 17446",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/100000",
            "value": 1180887,
            "range": "± 81853",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000000",
            "value": 7129162,
            "range": "± 28624",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/0",
            "value": 1130170,
            "range": "± 49127",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/1",
            "value": 1185352,
            "range": "± 48111",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/2",
            "value": 1343902,
            "range": "± 53387",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/0",
            "value": 720289,
            "range": "± 15266",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/1",
            "value": 765466,
            "range": "± 7851",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/2",
            "value": 820906,
            "range": "± 9551",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/0",
            "value": 23715,
            "range": "± 518",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/1",
            "value": 76022,
            "range": "± 1166",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/2",
            "value": 145489,
            "range": "± 4210",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "103590845+mulmarta@users.noreply.github.com",
            "name": "mulmarta",
            "username": "mulmarta"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "6d107b881cc16847e5867bceba35985097943d00",
          "message": "Add more Python FFI examples (#90)\n\n* Add more Python FFI examples\r\n\r\n* Make .py files separate\r\n\r\n---------\r\n\r\nCo-authored-by: Marta Mularczyk <mulmarta@amazon.com>",
          "timestamp": "2024-02-26T15:20:06-05:00",
          "tree_id": "2966d4710a3204a9e66ea96194fbfa6048706071",
          "url": "https://github.com/awslabs/mls-rs/commit/6d107b881cc16847e5867bceba35985097943d00"
        },
        "date": 1708979064194,
        "tool": "cargo",
        "benches": [
          {
            "name": "group_application/CipherSuite(1)/100",
            "value": 503994,
            "range": "± 11048",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000",
            "value": 515640,
            "range": "± 12892",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/10000",
            "value": 570976,
            "range": "± 14197",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/100000",
            "value": 1156782,
            "range": "± 32721",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000000",
            "value": 6928774,
            "range": "± 129202",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/0",
            "value": 1109971,
            "range": "± 56588",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/1",
            "value": 1171438,
            "range": "± 39886",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/2",
            "value": 1324477,
            "range": "± 27043",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/0",
            "value": 725772,
            "range": "± 23409",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/1",
            "value": 774869,
            "range": "± 10917",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/2",
            "value": 828842,
            "range": "± 16969",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/0",
            "value": 23917,
            "range": "± 394",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/1",
            "value": 77373,
            "range": "± 1366",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/2",
            "value": 145544,
            "range": "± 2989",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "tomleavy@amazon.com",
            "name": "Tom Leavy",
            "username": "tomleavy"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "7d8c89864cdb22291a3249958a50aea4012733e0",
          "message": "[uniffi] Add support for custom GroupStateStorage interface (#86)\n\n* [uniffi] Add support for custom GroupStateStorage interface\r\n\r\n* Allow external languages to implement callbacks\r\n\r\n* Remove unwrap from group_state.rs\r\n\r\n* Fix simple_scenario_sync and remove async for now\r\n\r\n* Ignore async tests",
          "timestamp": "2024-02-27T10:07:16-05:00",
          "tree_id": "9ece27a3c10be1afbfcf7ec4d4249846edc1257f",
          "url": "https://github.com/awslabs/mls-rs/commit/7d8c89864cdb22291a3249958a50aea4012733e0"
        },
        "date": 1709046712318,
        "tool": "cargo",
        "benches": [
          {
            "name": "group_application/CipherSuite(1)/100",
            "value": 547045,
            "range": "± 16144",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000",
            "value": 554626,
            "range": "± 8111",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/10000",
            "value": 575030,
            "range": "± 17789",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/100000",
            "value": 1166479,
            "range": "± 32578",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000000",
            "value": 7656169,
            "range": "± 29995",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/0",
            "value": 1125715,
            "range": "± 76821",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/1",
            "value": 1268541,
            "range": "± 69957",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/2",
            "value": 1400382,
            "range": "± 51976",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/0",
            "value": 733485,
            "range": "± 18090",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/1",
            "value": 778330,
            "range": "± 8825",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/2",
            "value": 832645,
            "range": "± 6905",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/0",
            "value": 23833,
            "range": "± 12908",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/1",
            "value": 77003,
            "range": "± 1935",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/2",
            "value": 147391,
            "range": "± 1727",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "103590845+mulmarta@users.noreply.github.com",
            "name": "mulmarta",
            "username": "mulmarta"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "3efaea28919b017ddbe1558002dfaa5ff6cbc2b3",
          "message": "Fix nightly clippy warning (#93)",
          "timestamp": "2024-02-28T09:21:33-05:00",
          "tree_id": "3ced740b35ee3d52dda44b2941ebbeca5452d666",
          "url": "https://github.com/awslabs/mls-rs/commit/3efaea28919b017ddbe1558002dfaa5ff6cbc2b3"
        },
        "date": 1709130370760,
        "tool": "cargo",
        "benches": [
          {
            "name": "group_application/CipherSuite(1)/100",
            "value": 546519,
            "range": "± 4661",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000",
            "value": 551739,
            "range": "± 3905",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/10000",
            "value": 608981,
            "range": "± 19782",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/100000",
            "value": 1190907,
            "range": "± 32882",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000000",
            "value": 6932062,
            "range": "± 55560",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/0",
            "value": 1139471,
            "range": "± 51041",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/1",
            "value": 1246729,
            "range": "± 56000",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/2",
            "value": 1329653,
            "range": "± 70241",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/0",
            "value": 725025,
            "range": "± 13000",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/1",
            "value": 768966,
            "range": "± 26040",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/2",
            "value": 827227,
            "range": "± 5655",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/0",
            "value": 23717,
            "range": "± 248",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/1",
            "value": 75935,
            "range": "± 2401",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/2",
            "value": 144916,
            "range": "± 1453",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "mgeisler@google.com",
            "name": "Martin Geisler",
            "username": "mgeisler"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "de125ef942564d3b4029eb0e4c3ab16656b1955d",
          "message": "Add a `generate_python_tests!` macro (#91)\n\nThe macro generates tests for Python scripts found next to the\r\nintegration test.\r\n\r\nThis saves a bit of boiler-plate code at the point where the test is\r\ncreated. It also allows us to quickly see if there are gaps in the\r\ntest coverage between the sync and async code.\r\n\r\nThis comes at the expense of more “magic” in the form of the macro.",
          "timestamp": "2024-02-28T18:11:30+01:00",
          "tree_id": "771931a339fe2b87a543263fbbfbbad42b11429f",
          "url": "https://github.com/awslabs/mls-rs/commit/de125ef942564d3b4029eb0e4c3ab16656b1955d"
        },
        "date": 1709140556193,
        "tool": "cargo",
        "benches": [
          {
            "name": "group_application/CipherSuite(1)/100",
            "value": 511601,
            "range": "± 15576",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000",
            "value": 518621,
            "range": "± 15434",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/10000",
            "value": 571825,
            "range": "± 13678",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/100000",
            "value": 1176613,
            "range": "± 23469",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000000",
            "value": 7202714,
            "range": "± 34516",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/0",
            "value": 1124008,
            "range": "± 81133",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/1",
            "value": 1193090,
            "range": "± 59668",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/2",
            "value": 1326640,
            "range": "± 39095",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/0",
            "value": 719217,
            "range": "± 13548",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/1",
            "value": 765786,
            "range": "± 58027",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/2",
            "value": 822930,
            "range": "± 11290",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/0",
            "value": 23582,
            "range": "± 158",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/1",
            "value": 76362,
            "range": "± 1692",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/2",
            "value": 146205,
            "range": "± 1681",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "mgeisler@google.com",
            "name": "Martin Geisler",
            "username": "mgeisler"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "da7263fe26a248403cdfdc9fc4e147d332fdcaa7",
          "message": "Tell `rustfmt` about the edition we use (#96)\n\nMy editor (Emacs) likes to format individual files by sending them to\r\n`rustfmt`. This fails without a configuration file to set the edition\r\nsince `rustfmt` (when executed alone, not via `cargo fmt`) defaults to\r\nthe good old Rust 2015 edition.",
          "timestamp": "2024-03-05T16:20:32-05:00",
          "tree_id": "ea354b89a1f6e63b1889ad21381dc9ae70f78d68",
          "url": "https://github.com/awslabs/mls-rs/commit/da7263fe26a248403cdfdc9fc4e147d332fdcaa7"
        },
        "date": 1709673898031,
        "tool": "cargo",
        "benches": [
          {
            "name": "group_application/CipherSuite(1)/100",
            "value": 528654,
            "range": "± 17750",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000",
            "value": 514879,
            "range": "± 34436",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/10000",
            "value": 572562,
            "range": "± 15602",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/100000",
            "value": 1172630,
            "range": "± 29120",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000000",
            "value": 7669967,
            "range": "± 284136",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/0",
            "value": 1115692,
            "range": "± 96441",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/1",
            "value": 1218267,
            "range": "± 29121",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/2",
            "value": 1339794,
            "range": "± 31468",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/0",
            "value": 721378,
            "range": "± 35755",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/1",
            "value": 766009,
            "range": "± 9151",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/2",
            "value": 823897,
            "range": "± 10423",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/0",
            "value": 23589,
            "range": "± 834",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/1",
            "value": 76123,
            "range": "± 1093",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/2",
            "value": 146176,
            "range": "± 1240",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "mgeisler@google.com",
            "name": "Martin Geisler",
            "username": "mgeisler"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "19ec995accb2101c7f2009fb668e1e3f0c6efa33",
          "message": "[uniffi] Expose `KeyPackage` fields (#102)",
          "timestamp": "2024-03-05T16:20:56-05:00",
          "tree_id": "2a3f4a762964ca64d2e9ff306c12bc8cfd6cfd0d",
          "url": "https://github.com/awslabs/mls-rs/commit/19ec995accb2101c7f2009fb668e1e3f0c6efa33"
        },
        "date": 1709673915225,
        "tool": "cargo",
        "benches": [
          {
            "name": "group_application/CipherSuite(1)/100",
            "value": 539507,
            "range": "± 13406",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000",
            "value": 529302,
            "range": "± 18619",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/10000",
            "value": 605063,
            "range": "± 35740",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/100000",
            "value": 1175877,
            "range": "± 35713",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000000",
            "value": 7533914,
            "range": "± 29078",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/0",
            "value": 1115093,
            "range": "± 40006",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/1",
            "value": 1211962,
            "range": "± 39077",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/2",
            "value": 1314264,
            "range": "± 47044",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/0",
            "value": 723947,
            "range": "± 15005",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/1",
            "value": 769313,
            "range": "± 22915",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/2",
            "value": 825973,
            "range": "± 10065",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/0",
            "value": 23620,
            "range": "± 205",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/1",
            "value": 76445,
            "range": "± 1120",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/2",
            "value": 145524,
            "range": "± 1185",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "mgeisler@google.com",
            "name": "Martin Geisler",
            "username": "mgeisler"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "1daa244de5627c327e4ce3bcfe001ca611c4db70",
          "message": "[uniffi] Enable coverage for UniFFI Python tests (#95)\n\nSetting a few environment variables should be enough to give us\r\ncoverage information for the Python integration tests. Based on\r\n\r\n  https://github.com/taiki-e/cargo-llvm-cov#get-coverage-of-external-tests\r\n\r\nRelated to #81.",
          "timestamp": "2024-03-05T17:02:37-05:00",
          "tree_id": "34764c643b7d6e257ba8e814e958a9c0a6505a9e",
          "url": "https://github.com/awslabs/mls-rs/commit/1daa244de5627c327e4ce3bcfe001ca611c4db70"
        },
        "date": 1709676423064,
        "tool": "cargo",
        "benches": [
          {
            "name": "group_application/CipherSuite(1)/100",
            "value": 546043,
            "range": "± 16722",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000",
            "value": 553747,
            "range": "± 14548",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/10000",
            "value": 610270,
            "range": "± 8704",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/100000",
            "value": 1159669,
            "range": "± 41167",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000000",
            "value": 7994977,
            "range": "± 36130",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/0",
            "value": 1127115,
            "range": "± 61997",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/1",
            "value": 1234980,
            "range": "± 88094",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/2",
            "value": 1367038,
            "range": "± 41587",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/0",
            "value": 721061,
            "range": "± 17466",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/1",
            "value": 767801,
            "range": "± 13587",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/2",
            "value": 824652,
            "range": "± 6414",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/0",
            "value": 23534,
            "range": "± 208",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/1",
            "value": 76564,
            "range": "± 1024",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/2",
            "value": 145475,
            "range": "± 1542",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "103590845+mulmarta@users.noreply.github.com",
            "name": "mulmarta",
            "username": "mulmarta"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "2f7d6d27b5f3dc3ae52a2726bbf8ad4b6e5b5b2a",
          "message": "Remove generics from GroupStateStorage (#94)\n\n* Remove generics from GroupStateStorage\r\n\r\n* wip\r\n\r\n* Fixup\r\n\r\n* Revert \"wip\"\r\n\r\nThis reverts commit edba2f38b9ea798a2bded2e868563b5809336dd4.\r\n\r\n---------\r\n\r\nCo-authored-by: Marta Mularczyk <mulmarta@amazon.com>",
          "timestamp": "2024-03-05T17:02:48-05:00",
          "tree_id": "134f9d7370a3bdc30821d41cadcde8da856129c3",
          "url": "https://github.com/awslabs/mls-rs/commit/2f7d6d27b5f3dc3ae52a2726bbf8ad4b6e5b5b2a"
        },
        "date": 1709676433335,
        "tool": "cargo",
        "benches": [
          {
            "name": "group_application/CipherSuite(1)/100",
            "value": 546928,
            "range": "± 7049",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000",
            "value": 552562,
            "range": "± 17327",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/10000",
            "value": 608495,
            "range": "± 40908",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/100000",
            "value": 1191811,
            "range": "± 31228",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000000",
            "value": 7105603,
            "range": "± 30572",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/0",
            "value": 1151742,
            "range": "± 45209",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/1",
            "value": 1255889,
            "range": "± 48747",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/2",
            "value": 1382987,
            "range": "± 121617",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/0",
            "value": 730144,
            "range": "± 15084",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/1",
            "value": 775364,
            "range": "± 12512",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/2",
            "value": 833692,
            "range": "± 11413",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/0",
            "value": 21592,
            "range": "± 230",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/1",
            "value": 70121,
            "range": "± 1787",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/2",
            "value": 134896,
            "range": "± 1175",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "mgeisler@google.com",
            "name": "Martin Geisler",
            "username": "mgeisler"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "7b1a4d00338a361ad9d0a92d3b480e1aff82a6cb",
          "message": "[uniffi] Rename enum variants to avoid collision (#101)",
          "timestamp": "2024-03-06T09:25:47-05:00",
          "tree_id": "fa86f785bd06fd6845198effa3b8f9ce8fd1ccd7",
          "url": "https://github.com/awslabs/mls-rs/commit/7b1a4d00338a361ad9d0a92d3b480e1aff82a6cb"
        },
        "date": 1709735406581,
        "tool": "cargo",
        "benches": [
          {
            "name": "group_application/CipherSuite(1)/100",
            "value": 511143,
            "range": "± 31424",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000",
            "value": 515549,
            "range": "± 10201",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/10000",
            "value": 572254,
            "range": "± 12728",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/100000",
            "value": 1154410,
            "range": "± 21530",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000000",
            "value": 7927693,
            "range": "± 26074",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/0",
            "value": 1108537,
            "range": "± 56390",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/1",
            "value": 1218072,
            "range": "± 46303",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/2",
            "value": 1323269,
            "range": "± 43632",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/0",
            "value": 724413,
            "range": "± 14050",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/1",
            "value": 765694,
            "range": "± 10899",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/2",
            "value": 827665,
            "range": "± 13361",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/0",
            "value": 21508,
            "range": "± 334",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/1",
            "value": 70323,
            "range": "± 1037",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/2",
            "value": 135669,
            "range": "± 3073",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "103590845+mulmarta@users.noreply.github.com",
            "name": "mulmarta",
            "username": "mulmarta"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "4606da09135e19d2d428a197db4b6cd7f247cd46",
          "message": "[Bugfix] Derive external pub extension from the new and not old key schedule (#108)\n\n* [Bugfix] Derive external pub extension from the new and not old key schedule\r\n\r\n* Make clippy stable\r\n\r\n* Change test cipher suite to one supported by WASM\r\n\r\n---------\r\n\r\nCo-authored-by: Marta Mularczyk <mulmarta@amazon.com>",
          "timestamp": "2024-03-08T11:20:18-05:00",
          "tree_id": "40e5385b31ff2e60ba8a94f2e866faa6cd6e5923",
          "url": "https://github.com/awslabs/mls-rs/commit/4606da09135e19d2d428a197db4b6cd7f247cd46"
        },
        "date": 1709915078112,
        "tool": "cargo",
        "benches": [
          {
            "name": "group_application/CipherSuite(1)/100",
            "value": 498633,
            "range": "± 6318",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000",
            "value": 506496,
            "range": "± 5453",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/10000",
            "value": 563498,
            "range": "± 43517",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/100000",
            "value": 1136204,
            "range": "± 83152",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000000",
            "value": 6869367,
            "range": "± 492643",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/0",
            "value": 1100971,
            "range": "± 116704",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/1",
            "value": 1217535,
            "range": "± 43026",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/2",
            "value": 1321823,
            "range": "± 48734",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/0",
            "value": 714233,
            "range": "± 6221",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/1",
            "value": 762978,
            "range": "± 22141",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/2",
            "value": 814983,
            "range": "± 4707",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/0",
            "value": 21881,
            "range": "± 459",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/1",
            "value": 72431,
            "range": "± 1751",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/2",
            "value": 139962,
            "range": "± 1608",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "mgeisler@google.com",
            "name": "Martin Geisler",
            "username": "mgeisler"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "979b8cf8a99c7b07056d3bc4bc951285013ee312",
          "message": "[uniffi] Fix missing return in Python test (#105)\n\nThis was not actually used yet, but it should be used eventually.",
          "timestamp": "2024-03-08T13:42:16-05:00",
          "tree_id": "2c1f9802cb3d5fa52a813ef69479c792163c25ed",
          "url": "https://github.com/awslabs/mls-rs/commit/979b8cf8a99c7b07056d3bc4bc951285013ee312"
        },
        "date": 1709923601186,
        "tool": "cargo",
        "benches": [
          {
            "name": "group_application/CipherSuite(1)/100",
            "value": 501004,
            "range": "± 5327",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000",
            "value": 509125,
            "range": "± 2695",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/10000",
            "value": 564884,
            "range": "± 37625",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/100000",
            "value": 1167649,
            "range": "± 69495",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000000",
            "value": 9151265,
            "range": "± 456475",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/0",
            "value": 1073548,
            "range": "± 59397",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/1",
            "value": 1142737,
            "range": "± 33924",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/2",
            "value": 1307421,
            "range": "± 56447",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/0",
            "value": 709329,
            "range": "± 54988",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/1",
            "value": 755762,
            "range": "± 4916",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/2",
            "value": 815553,
            "range": "± 3589",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/0",
            "value": 21581,
            "range": "± 233",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/1",
            "value": 70331,
            "range": "± 1027",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/2",
            "value": 136101,
            "range": "± 1177",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "mgeisler@google.com",
            "name": "Martin Geisler",
            "username": "mgeisler"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "34b9ac2a83b6661d035b913d36a428fd531f5895",
          "message": "[uniffi] Use data classes in Python test (#104)",
          "timestamp": "2024-03-08T13:42:31-05:00",
          "tree_id": "64d1f3d4368555631e2497d664353f450ce63e1f",
          "url": "https://github.com/awslabs/mls-rs/commit/34b9ac2a83b6661d035b913d36a428fd531f5895"
        },
        "date": 1709923608390,
        "tool": "cargo",
        "benches": [
          {
            "name": "group_application/CipherSuite(1)/100",
            "value": 501123,
            "range": "± 6420",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000",
            "value": 508281,
            "range": "± 7444",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/10000",
            "value": 565677,
            "range": "± 14990",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/100000",
            "value": 1169454,
            "range": "± 46184",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000000",
            "value": 7764922,
            "range": "± 28325",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/0",
            "value": 1106846,
            "range": "± 45274",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/1",
            "value": 1185540,
            "range": "± 49351",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/2",
            "value": 1326842,
            "range": "± 49732",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/0",
            "value": 713649,
            "range": "± 18462",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/1",
            "value": 759375,
            "range": "± 46968",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/2",
            "value": 817889,
            "range": "± 5777",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/0",
            "value": 21519,
            "range": "± 283",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/1",
            "value": 70293,
            "range": "± 964",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/2",
            "value": 134695,
            "range": "± 1096",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "mgeisler@google.com",
            "name": "Martin Geisler",
            "username": "mgeisler"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "2d92710155695c1cc07b9ca952e261bbc882c4be",
          "message": "[uniffi] Add `simple_scenario` unit test (#97)\n\nThis simply exercises the new code from Rust.",
          "timestamp": "2024-03-08T14:13:53-05:00",
          "tree_id": "231fe6ad4f8bd515081742a78a9dc37d27e0ad80",
          "url": "https://github.com/awslabs/mls-rs/commit/2d92710155695c1cc07b9ca952e261bbc882c4be"
        },
        "date": 1709925493667,
        "tool": "cargo",
        "benches": [
          {
            "name": "group_application/CipherSuite(1)/100",
            "value": 504051,
            "range": "± 9394",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000",
            "value": 512349,
            "range": "± 7101",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/10000",
            "value": 566940,
            "range": "± 31104",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/100000",
            "value": 1147690,
            "range": "± 23879",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000000",
            "value": 7225306,
            "range": "± 28287",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/0",
            "value": 1079095,
            "range": "± 61923",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/1",
            "value": 1187485,
            "range": "± 44286",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/2",
            "value": 1310076,
            "range": "± 38436",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/0",
            "value": 710886,
            "range": "± 31252",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/1",
            "value": 758095,
            "range": "± 7181",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/2",
            "value": 814112,
            "range": "± 7973",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/0",
            "value": 21445,
            "range": "± 194",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/1",
            "value": 69572,
            "range": "± 993",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/2",
            "value": 134182,
            "range": "± 15857",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "mgeisler@google.com",
            "name": "Martin Geisler",
            "username": "mgeisler"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "f23c6e464a8ff68fafa4e0749b6ca6d025d4f5fa",
          "message": "Fix documentation for `CommitOutput::rather_tree` (#109)\n\nThe ratchet tree extension is configured in https://docs.rs/mls-rs/latest/mls_rs/group/mls_rules/struct.CommitOptions.html.",
          "timestamp": "2024-03-13T10:11:33+01:00",
          "tree_id": "0e7e47e928866aca68de08aeff1f71b477a4a071",
          "url": "https://github.com/awslabs/mls-rs/commit/f23c6e464a8ff68fafa4e0749b6ca6d025d4f5fa"
        },
        "date": 1710321349875,
        "tool": "cargo",
        "benches": [
          {
            "name": "group_application/CipherSuite(1)/100",
            "value": 503739,
            "range": "± 6826",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000",
            "value": 511443,
            "range": "± 13201",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/10000",
            "value": 565402,
            "range": "± 28704",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/100000",
            "value": 1155471,
            "range": "± 27529",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000000",
            "value": 6991968,
            "range": "± 39560",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/0",
            "value": 1073170,
            "range": "± 46898",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/1",
            "value": 1213126,
            "range": "± 34190",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/2",
            "value": 1335594,
            "range": "± 51701",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/0",
            "value": 713628,
            "range": "± 11091",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/1",
            "value": 760786,
            "range": "± 10112",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/2",
            "value": 816613,
            "range": "± 4458",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/0",
            "value": 21518,
            "range": "± 698",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/1",
            "value": 70451,
            "range": "± 954",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/2",
            "value": 135797,
            "range": "± 1535",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "mgeisler@google.com",
            "name": "Martin Geisler",
            "username": "mgeisler"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "c2aeb936c67359c7ab313ee411cbf287b95de69f",
          "message": "[uniffi] Use Python 3.9 type hints in tests (#106)\n\nI believe this is the recommended way for modern Python code. Since\r\nthis only affects the tests, I hope it’s okay to require a recent\r\nPython.\r\n\r\nThis also fixes a few signatures in PythonGroupStateStorage to use the\r\nsame signature as in the parent class.",
          "timestamp": "2024-03-13T11:32:35+01:00",
          "tree_id": "869bf1612cc992d1dd1c4aceb6b5dc502314fdc9",
          "url": "https://github.com/awslabs/mls-rs/commit/c2aeb936c67359c7ab313ee411cbf287b95de69f"
        },
        "date": 1710326214931,
        "tool": "cargo",
        "benches": [
          {
            "name": "group_application/CipherSuite(1)/100",
            "value": 499773,
            "range": "± 7353",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000",
            "value": 508256,
            "range": "± 4680",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/10000",
            "value": 564474,
            "range": "± 20917",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/100000",
            "value": 1145116,
            "range": "± 35575",
            "unit": "ns/iter"
          },
          {
            "name": "group_application/CipherSuite(1)/1000000",
            "value": 7719925,
            "range": "± 28272",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/0",
            "value": 1123971,
            "range": "± 48920",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/1",
            "value": 1227909,
            "range": "± 62231",
            "unit": "ns/iter"
          },
          {
            "name": "group_commit/CipherSuite(1)/2",
            "value": 1340928,
            "range": "± 73091",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/0",
            "value": 718069,
            "range": "± 14682",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/1",
            "value": 767737,
            "range": "± 4852",
            "unit": "ns/iter"
          },
          {
            "name": "group_receive_commit/CipherSuite(1)/2",
            "value": 826865,
            "range": "± 5355",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/0",
            "value": 21491,
            "range": "± 640",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/1",
            "value": 70280,
            "range": "± 3379",
            "unit": "ns/iter"
          },
          {
            "name": "group_serialize/CipherSuite(1)/2",
            "value": 135373,
            "range": "± 1377",
            "unit": "ns/iter"
          }
        ]
      }
    ]
  }
}