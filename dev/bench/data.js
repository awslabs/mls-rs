window.BENCHMARK_DATA = {
  "lastUpdate": 1699309627304,
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
      }
    ]
  }
}