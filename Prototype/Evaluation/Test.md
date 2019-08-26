## Synthetic data speed test
### Test on server 2 (client) & server 3 (keyserver & 4 servers)
#### Setup

* File size = 2 GB (2048 MB)
* Key generate batch size = 3000
* Optimal compute threshold = 3000
* Sketch table line size = 2^16
* Short hash send size = 16 bit

#### Performance 

* Upload : 28.320462s = 72.32 MB/s
* Download : 18.633074s = 109.91 MB/s


### Test on node11 (client) & node12 (keyserver) & node13~16 (4 storage servers)
#### Setup

* File size = 2 GB (2048 MB)
* Key generate batch size = 3000
* Optimal compute threshold = 3000
* Sketch table line size = 2^16
* Short hash send size = 16 bit

#### Performance 

* Upload : 35.476392s = 57.73 MB/s
* Download : 21.014705s = 97.46 MB/s

## Key generate speed test

### Setup
* File size = 2 GB (2048 MB)
* Key generate batch size = 3000
* Optimal compute threshold = 3000
* Sketch table line size = 2^16
* Short hash send size = 16 bit

### Performance

> Average of 10 runs.

* Compute murmurhash time per chunk: 44.8 us
* Network latency per 3000 chunks: 0.1 s
* Generate key seed time per chunk: 0 us
* Update parameter time per chunk: 0.3 us
* Generate final key time per chunk: 4.2 us
* Compute optimal result time per 3000 chunks : 0.05 s

#### Key Generate Speed 

Average speed of generate one key for each chunk = 82.6 us