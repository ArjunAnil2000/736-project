# Ideas

Document capturing potential project proposals.

## Table

| Sl no. | Idea |
| --- | --- |
| 1. | Survey of eBPF policies |
| 2. | (LDOS continuation) AI code evolution on cache_ext |
| 3. | (LDOS new) Try code evolution on a new BPF interface (bpf_fault) |
| 4. | Does adding a bpf interface cause performance drops? |
| 5. | Cache_ext on a host containing SSD and HDD |

## 1. Survey of eBPF policies

- **Idea:** Survey all the eBPF polices that have been proposed and executed.
  - Survey all the popularly used policies (like sched_ext etc) that have been upstreamed into eBPF
  - Survey all the policies that have been proposed and implemented but never upstreamed into the linux kernel (eg. cache_ext).
    - Explore why these policies where never upstreamed (not enough people etc).
  - Existing papers I could find with a quick search:
    - https://arxiv.org/pdf/2410.00026 (The eBPF Runtime in the Linux Kernel)
    - https://dl.acm.org/doi/10.1145/3672197.3673429 (An Empirical Study on the Challenges of eBPF Application Development)
- **Result:** A survey paper of all the policies.
- **The big question mark:** How do we do an evaluation section for this? It's for existing policies.

## 2. (LDOS continuation) AI code evolution on cache_ext

- **Idea:** Continue working on the current LDOS stream of projects I was doing.
  - Linux page cache policy using AI code evolution tools (like Coral).
  - Interesting systems angle would be the following question:
    - *"How do we evaluate how good a page cache policy is?"*. We can ask this question using a couple of different angles:
      - Use only metrics that can be polled from the kernel for this calculation (like swap-ins, refault-rate, read-bytes-from-disk).
      - Use metrics from the resident application (For eg. if we're doing YCSB on a database: throughput, GET/SCAN latencies like avg, p99)
- **Result:** My hypothesis is that metrics polled from the kernel will be insufficient to predict how good a policy is. If we give the 2 sets of metrics to an AI code evolution to evolve from, the latter (the one that has the application metrics) should give the better policy.
- **The big question mark:** This one might end up being code evolution heavy rather than systems?

## 3. (LDOS new) Try code evolution on a new BPF interface (bpf_fault)

- **Idea:** Use code evolution on a new BPF interface (bpf_fault) -- somewhere it absolutelty does not make any sense.
  - The bpf_fault (page fault eBPF struct_ops interface) recently won best paper awards at SOSP. The paper describes how one could the interface to construct *mechanisms* (and not policies) to improve performance in live migration of VMs or dynamically linked libraries in Chrome.
  - This is somewhere AI code evolution, in the traditional sense, makes absolutely no sense -- we see policy evolution not mechanism evolution.
  - Try to use AI to evolve a bpf_fault interface for a particular workload (let's say a levelDB get-scan workload) where the page fault mechanism intuitively should not have any improvement it can offer. (Maybe we can have the major page fault handler fetch extra pages so that the next page grabbed would be a minor page fault? -- mechanisms, not policies).
- **Result:** Could be either of a) the AI code evolution finds a useful mechanism for this particular workload on bpf_fault; or b) the AI code evolution fails miserably and we can claim that the models are lacking right now.
- **The big question mark:** This one might end with a result that is not particularly useful.

## 4. Does adding a bpf interface cause performance drops?

- **Idea:** Choose a eBPF interface kernel where the commits adding the interface can be reverted without really changing the policies implemented underneath.
  - As the title indicates, this idea involves determining if adding a bpf interface where it was not there before introduce performance problems. 
  - The motivation behind this would be that while eBPF struct_ops interfaces allow flexibility for certain workloads, for the majority of applications that are loaded onto say my laptop, will not use this interface. So by adding this interface are we sacrificing performance for the "general" applications while increasing performance for a specific subset?
  - I think we can have 2 sets of experiments here:
    - Compare a specialized workload (cache_ext paper had one specific workload): original kernel (without eBPF struct_ops hooks) vs modified kernel without the custom policy vs modified kernel with the custom kernel.
    - Take a generic application (no idea what to choose here, maybe we can do bench tester like elbencho for file systems or libcachesim or something)
- **Result:** A comparison that reflects either a) adding the interface does cost some performance; b) adding the interface is good generally.
- **The big question mark:** Finding the right workload/application to run might be problematic?

## 5. Cache_ext on a host containing SSD and HDD

- **Idea:** (Motived from the TMO paper of sorts). Due to the difference of performance characteristics in HDD and SSD, it means that a linux page cache policy that has a higher refault rate for page evicted to the HDD should theoratically perform worse than a policy that evicts pages belonging to files on SSD. The project would be to develop a eBPF policy which does this.
  - This would involve understanding eBPF, how we could potentially detect if a page belongs to a file that is in a HDD/SSD or whether we would have to store that in a eBPF map based on PID etc.
  - Experiments that we can do on this should be abundant but limited -- all I can think are of benchmarks involving read/scan of a file and toy programs that re-read a page.
- **Result:** A report that should show improvement in performance due to this policy.
- **The big question mark:** Would there be a workload that shows behaviour like this? i.e reading files from a HDD and SSD? Another potential issue is finding a host that has some kind of support for this? We could maybe plug in an external hard-drive into a computer and "pretend" it's the slower HDD even though the latency/throughput would have much more of a hit (USB connection so).
