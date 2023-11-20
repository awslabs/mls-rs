window.BENCHMARK_DATA = {
  "lastUpdate": 1700498629821,
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
      }
    ]
  }
}