window.BENCHMARK_DATA = {
  "lastUpdate": 1699481552583,
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
      }
    ]
  }
}