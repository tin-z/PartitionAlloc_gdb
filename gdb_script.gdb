## Config
source ~/.gdbinit
source /<path>/src/tools/gdb/gdbinit


tbreak ../../third_party/blink/renderer/core/css/css_variable_data.cc:80

run

source /<path>/PartitionAlloc_gdb/superpage_utils.py

!rm -rf /tmp/gdb.log
set logging file /tmp/gdb.log
set logging on


## inspect superpage list for that partitionroot
set $super_page_addr=$rax
pa_print_slot_span_info --super_page_list $super_page_addr

### dump partitionroot
pa_print_slot_span_info --root $super_page_addr --is_page --skip_tcache_search

### dump thread cache info
pa_print_slot_span_info --tcache $super_page_addr --is_page


## bp1
## (before) thread bucket and partitionBucket stats
break ../../v8/src/objects/backing-store.cc:291
c
pa_print_slot_span_info --trace_thread_bucket $super_page_addr --slot_index 0
pa_print_slot_span_info --trace_partition_bucket $super_page_addr --slot_index 0

## bp2
## After thread bucket and partitionBucket stats
c
pa_print_slot_span_info --trace_thread_bucket $super_page_addr --slot_index 0
pa_print_slot_span_info --trace_partition_bucket $super_page_addr --slot_index 0

## bp3
## trace allocation
pa_collect_address --thread 1 --log /tmp/pa_alloc.log --command "bt" ../../base/allocator/partition_allocator/partition_root.h:1922 this bucket_index
c


## bp4
## Search object sprayed
delete breakpoints
break ../../v8/src/objects/backing-store.cc:291 thread 1
c
pa_search $super_page_addr "41 41 41 41 41 41 41 41"


## search objects allocated on the fastmalloc partition requesting a slot_size 0x10 chunk/object
## it's imprecise, and some objects are missing from the list (shared_ptr, audioarray)
pa_search_object_size --blink --v8 0x10


