import gdb
import re

kPageMask_custom = 0x0000ffffffffffff
kSuperPageBaseMask = 0xffffffffffe00000
kSuperPageOffsetMask = 0x1fffff
kSuperPageSize = 0x200000
kSuperPageAlignment = kSuperPageSize
kPartitionPageShift = 14
kPartitionPageSize =  1 << kPartitionPageShift

SystemPageShift = 12 #// 4kB 0x1000
SystemPageSize = 1 << SystemPageShift
NumPartitionPagesPerSuperPage = kSuperPageSize >> kPartitionPageShift


partition_bucket_size = 40
sz_partitionpage_metadata = 0x20

space = " "*4
print_dict = lambda x : "\n".join([f"{space}{k} = 0x{v:x}" for k,v in x.items()]) + "\n"
print_flag = lambda x : "\n".join([f"{space}{space}{k} = {v}" for k,v in x.items()]) + "\n"
print_dict_2 = lambda x : f"{space}(" + ", ".join([f"{k}=0x{v:x}" for k,v in x.items()]) + ")"

def print_key_value(key, dict_, space=space, hex_fmt=False):
    return f"{space}{key} = {dict_[key]}" if not hex_fmt else f"{space}{key} = 0x{dict_[key]:x}"

def print_index_per_value(key, dict_,  space=space):
    output = []
    for i,v in enumerate(dict_[key]):
        output.append(f"[{i:x}] = 0x{v:x}")
    return f"{space}{key} = [" + ", ".join(output) + "]"


def print_keys_values(dict_, space=space):
    return "\n".join([f"{space}{k} = 0x{v:x}" for k,v in dict_.items()])



def is_superpage_address(super_page):
    return addr % kSuperPageAlignment == 0


def get_first_partition_page(super_page):
    return super_page + kPartitionPageSize 


def get_last_partition_page(super_page):
    last_guard_page = super_page + (kSuperPageSize - kPartitionPageSize)
    return last_guard_page - kPartitionPageSize


def get_super_page(address):
    return address & kSuperPageBaseMask


def get_partition_page_index(addr):
    return (addr & kSuperPageOffsetMask) >> kPartitionPageShift


def get_slot_span_start(super_page, partition_page_index):
    return super_page + (partition_page_index << kPartitionPageShift)



root_QuarantineMode = ["kAlwaysDisabled", "kDisabledByDefault", "kEnabled"]
root_ScanMode = ["kDisabled", "kEnabled"]
root_BucketDistribution = ["kDefault", "kCoarser", "kDenser"]



class pa_SetPartitionRoot(gdb.Command):
    """Usage: pa_set_groot <address>
    Declare variable $groot as the Partitionroot. 

    example:
    set $groot = (partition_alloc::PartitionRoot<1> *) 0x58b4c57b1a8

    Note: g_root is defined in base/allocator/partition_allocator/shim/allocator_shim_default_dispatch_to_partition_alloc.cc 
    also we can find it's address by printing 'this' on partition_alloc::PartitionRoot<true>::AllocWithFlagsNoHooks breakpoint
    """
    def __init__(self):
        super(pa_SetPartitionRoot, self).__init__("pa_set_groot", gdb.COMMAND_USER)
        self.groot = 0

    def invoke(self, arg, from_tty):
        args = gdb.string_to_argv(arg)
        if len(args) != 1:
            print("Usage: pa_set_groot <address>")
            return
        if self.groot:
            print(f"PartitionRoot groot was already set to 0x{self.groot:x}")
        else:
            addr = args[0].strip().lower()
            self.groot = int(addr, 16 if addr.startswith("0x") else 10)
            gdb.execute(f"set $groot = (partition_alloc::PartitionRoot<1> *) 0x{self.groot:x}")


class pa_PrintMetadataPage(gdb.Command):
    """Usage: pa_print_slot_span_info <object-address>
    Print 
        super-page address
        slot-span (PartitionPage) index
        slot-span metadata entry (related to the slot-span index)
        PartitionBucket
    """

    thread_caches = {}

    limit_output_freelist = -1



    def __init__(self):
        super(pa_PrintMetadataPage, self).__init__("pa_print_slot_span_info", gdb.COMMAND_USER)

    def print_usage(self):
        print(
            """Usage: pa_print_slot_span_info [options] <address|gdb-env>

            If no options are given dump general content of the partition root from the given address

            Options
                --help : print this message
                --root : the address represents a root object, dump it
                --buck : the address represent a PartitionBucket object, dump it
                --slot : the address represent a SlotSpanMetadata object, dump it
                --tcache : print thread cache info
                --free : print bucket thread cache and traverse its freelist
                --free_list : The address given is a PartitionFreelistEntry, so traverse it
                --is_page : #TODO: by enabling this flag, the address given is treated as a page address. Can be used to dump tcache and root without knowing their address
                --slot_index : this parameter is used in other commands to filter output per slot_index. For example '--trace_thread_bucket'
                --is_free : flag used to tell the script to print if the given address is part of a freelist somewhere (--slot_index must be declared)

                --trace_thread_bucket  : Retrieve thread buckets from an address of a super_page
                                         if slot_index was defined, then show only that specific bucket and traverse freelist_head linked-list

                --trace_partition_bucket : TODO: Retrieve partition buckets from an address of a super_page
                                           if slot_index was defined, then show only that specific bucket and traverse freelist_head linked-list
                                           and also traverse 'next_slot_span's linked-list

                --limit_freelist        : Change the static variable of the class used to print only last <N> elements of a linked-list 
                                          (default value: -1 which means print all the elements, 0 print none)

                --super_page_list       : Dump super page list associated to the partitionroot based on the super page address
                --skip_tcache_search    : Skip searching for thread caches
                --skip_root_search      : Skip root dumping


            example: dump slot span address (without dumping partition root)
                print_slot_span_info 0x20...........
                print_slot_span_info --root 0x65...........
                print_slot_span_info --pino 0x20...........
            """
        )


    def int(self, target, conv=10):
        addr = None
        target = target.strip().lower()
        try:
            if target.startswith('0x') or target.startswith('-0x'):
                addr = int(target, conv)
            else:
                addr = int(gdb.parse_and_eval(target))
        except Exception as ex:
            print(f"[x] Can't parse integer/symbol '{target}' exception: {ex}")
        return addr



    def invoke(self, arg, from_tty):
        args = gdb.string_to_argv(arg)
        print_help = False
        root_addr = None
        buck_addr = None
        slot_addr = None
        thread_cache_addr = None
        bucket_thread_cache_addr = None
        freelist_addr = None
        trace_thread_bucket_addr = None
        trace_partition_bucket_addr = None
        slot_index = -1
        is_page_addr = False
        print_super_pages_list = None
        check_is_free = False
        self.skip_tcache = False
        self.skip_root = False


        self.inferior = gdb.selected_inferior()

        if len(args) < 1:
            print_help = True
        else:
            if args[0].startswith('--'):
                while args and args[0].startswith('--'):
                    if args[0] == '--help' :
                        print_help = True
                        break
                    elif args[0] == '--root' and len(args) >= 2:
                        root_addr = self.int(args[1], 16)
                        args = args[2:]
                    elif args[0] == '--buck' and len(args) >= 2:
                        buck_addr= self.int(args[1], 16)
                        args = args[2:]
                    elif args[0] == '--slot' and len(args) >= 2:
                        slot_addr= self.int(args[1], 16)
                        args = args[2:]
                    elif args[0] == '--tcache' and len(args) >= 2:
                        thread_cache_addr= self.int(args[1], 16)
                        args = args[2:]
                    elif args[0] == '--free' and len(args) >= 2:
                        bucket_thread_cache_addr = self.int(args[1], 16)
                        args = args[2:]
                    elif args[0] == '--free_list' and len(args) >= 2:
                        freelist_addr = self.int(args[1], 16)
                        args = args[2:]
                    elif args[0] == '--slot_index' and len(args) >= 2:
                        slot_index = self.int(args[1], 16)
                        args = args[2:]
                    elif args[0] == '--trace_thread_bucket' and len(args) >= 2:
                        trace_thread_bucket_addr = self.int(args[1], 16)
                        args = args[2:]
                    elif args[0] == '--trace_partition_bucket' and len(args) >= 2:
                        trace_partition_bucket_addr = self.int(args[1], 16)
                        args = args[2:]
                    elif args[0] == '--limit_freelist' and len(args) >= 2:
                        pa_PrintMetadataPage.limit_output_freelist = self.int(args[1], 16)
                        args = args[2:]
                    elif args[0] == '--is_page' :
                        is_page_addr = True
                        args = args[1:]
                    elif args[0] == '--is_free' :
                        check_is_free = True
                        args = args[1:]
                    elif args[0] == '--skip_tcache_search' :
                        self.skip_tcache = True
                        args = args[1:]
                    elif args[0] == '--skip_root_search' :
                        self.skip_root = True
                        args = args[1:]

                    elif args[0] == '--super_page_list' :
                        print_super_pages_list = self.int(args[1], 16)
                        args = args[2:]
                    else:
                        print(f"Unknown option {args[0]}")
                        print_help = True
                        break
            else:
                addr = self.int(args[0], 16)
                if not addr:
                    self.print_usage()
                    return
                self.print_info(addr)

        if print_help:
            self.print_usage()
            return

        if root_addr:
            self.dump_root(root_addr, is_page=is_page_addr)

        if buck_addr:
            self.dump_bucket(buck_addr)

        if slot_addr:
            self.dump_slotspan_meta(slot_addr)

        if thread_cache_addr:
            self.dump_thread_cache(thread_cache_addr, is_page=is_page_addr)

        if bucket_thread_cache_addr:
            self.dump_thread_bucket(bucket_thread_cache_addr)

        if freelist_addr:
            self.dump_freelist(freelist_addr)

        if trace_thread_bucket_addr:
            self.trace_thread_bucket(trace_thread_bucket_addr, slot_index=slot_index, check_is_free=check_is_free)

        if trace_partition_bucket_addr:
            self.trace_partition_bucket(trace_partition_bucket_addr, slot_index=slot_index, check_is_free=check_is_free)

        if print_super_pages_list:
            self.get_super_page_list(print_super_pages_list)

        if len(args) == 1:
            addr = self.int(args[0], 16)
            if not addr:
                self.print_usage()
                return
            self.print_info(addr)




    def read_memory(self, addr, bytes_):
        mem = self.inferior.read_memory(addr, bytes_)
        return mem

    def read_short_from_memory(self, addr, sign=False):
        sz = 2
        mem = self.read_memory(addr, sz)
        frmt = "<H" if not sign else "<h"
        return struct.unpack(frmt, mem)[0]

    def read_int_from_memory(self, addr, sign=False):
        sz = 4
        mem = self.read_memory(addr, sz)
        frmt = "<I" if not sign else "<i"
        return struct.unpack(frmt, mem)[0]

    def read_long_from_memory(self, addr, sign=False):
        sz = 8
        mem = self.read_memory(addr, sz)
        frmt = "<Q" if not sign else "<q"
        return struct.unpack(frmt, mem)[0]

    def read_long_from_memory_be(self, addr, sign=False):
        sz = 8
        mem = self.read_memory(addr, sz)
        frmt = ">Q" if not sign else ">q"
        return struct.unpack(frmt, mem)[0]

    def get_thread_id(self):
        thread = gdb.selected_thread()
        return thread.num

    def get_thread_cache_candidates(self):
        thrd = self.get_thread_id()
        if thrd in pa_PrintMetadataPage.thread_caches:
            return pa_PrintMetadataPage.thread_caches[thrd]
        return []

    def set_thread_cache_candidates(self, tcache_list):
        thrd = self.get_thread_id()
        pa_PrintMetadataPage.thread_caches[thrd] = tcache_list


    def trace_thread_bucket(self, addr, slot_index=-1, check_is_free=False):
        str_ = []
        thread_cache = self.get_thread_cache_candidates()
        if not thread_cache:
            thread_cache = self.read_info(addr, return_thread_cache_list=True)
        if thread_cache:
            thrd_addr = thread_cache[0]
            current, (_thread_cache, _, _, _buckets) = self.read_thread_cache(thrd_addr)
            str_.append(f"[Thread-cache: 0x{thrd_addr:x}] " + print_key_value("thread_id_",_thread_cache,space="") + " " + print_key_value("root_", _thread_cache, space="",hex_fmt=True))
            if slot_index >= 0:
                if slot_index >= len(_buckets):
                    str_.append(f"[x] Invalid slot index {hex(slot_index)}")
                else:
                    str_ += self.dump_thread_bucket(_buckets[slot_index]['addr'], do_print=False)
            else:
                str_.append("\n".join(f"{space}Bucket [{hex(i).rjust(4,' ')}] slot_size: {hex(x['slot_size']).rjust(6,' ')}, freelist_head: {hex(x['freelist_head']).rjust(14,' ')} (count: {x['count']})  stored at 0x{x['addr']:x}" for i,x in enumerate(_buckets)))
        else:
            str_.append("[x] Couldn't find thread cache .. try changing address or dump root directly to cache the thread cache address")

        str_print = "\n".join(str_)
        if check_is_free:
            if hex(addr) in str_print:
                str_print += f"\n[+] {hex(addr)} is free"
            else:
                str_print += f"\n[-] {hex(addr)} is occupied"

        print(str_print)





    def trace_partition_bucket(self, addr, slot_index=-1, check_is_free=False):
        global space
        str_ = []
        root_addr = self.read_info(addr, return_super_page_list=True)
        if root_addr: 
            old_space = space
            space = ""
            buckets_address, sentinel_bucket, str_buckets_ = self.dump_root(root_addr, dump_only_buckets=True)
            space = old_space

            if slot_index >= 0:
                bucket_address, active_slot_spans_head = buckets_address[slot_index]
                str_.append(str_buckets_[slot_index])
                if active_slot_spans_head and active_slot_spans_head != sentinel_bucket["active_slot_spans_head"]:
                    str_ += self.dump_slotspan_meta(active_slot_spans_head, traverse_slot_spans=True, do_print=False)

            else:
                str_ += str_buckets_
        else:
            str_.append("[x] Couldn't find the root")

        str_print = "\n".join(str_)
        if check_is_free:
            if hex(addr) in str_print:
                str_print += f"\n[+] {hex(addr)} is free"
            else:
                str_print += f"\n[-] {hex(addr)} is occupied"

        print(str_print)



    def dump_super_pages(self, first_extent_addr, super_page_list=[]):
        page_mapping = []
        if first_extent_addr:
            if not super_page_list:
                super_page_list = self.read_SuperPageExtentEntry(first_extent_addr)
            for x in super_page_list:
                addr_tmp = x['addr'] & kSuperPageBaseMask
                num_consec = x['number_of_consecutive_super_pages']
                num_nonempty = x['number_of_nonempty_slot_spans']
                page_data_starts = addr_tmp + kPartitionPageSize
                page_data_ends = (addr_tmp + (num_consec * kSuperPageSize)) - kPartitionPageSize
                page_mapping.append(f"{space}0x{page_data_starts:x} - 0x{page_data_ends:x} (0x{num_consec:x}, 0x{num_nonempty:x})")
        str_ = [
            f"SuperPage mappings (based on extents sections):",
            "\n".join(page_mapping),
        ]
        return str_

    def dump_root(self, addr, dump_only_buckets=False, is_page=False):

        if is_page:
            addr = self.read_info(addr, return_super_page_list=True)

        root, buckets, sentinel_bucket, global_empty_slot_span_ring, flags = self.read_root(addr)
        thread_cache = []

        first_extent = root["first_extent"]
        if first_extent:
            thread_cache = self.get_thread_cache_candidates()
            if not thread_cache:
                if self.skip_tcache :
                    thread_cache = self.scan_for_thread_cache(addr, get_super_page(first_extent))
                    self.set_thread_cache_candidates(thread_cache)

        str_ = [
            f"[PartitionRoot 0x{addr:x}]",
            f"ThreadCache candidates: [{', '.join([hex(x) for x in thread_cache])}]",
            "\n".join(self.dump_super_pages(first_extent)),
            "",
            print_dict(root),
            f"{space}flags = \x7b",
            print_flag(flags),
            f"{space}\x7d",
            "global_empty_slot_span_ring: [" + ", ".join(global_empty_slot_span_ring) + "]",
        ]


        str_buckets_ = []
        buckets_address = []
        sentinel_slot_span = sentinel_bucket["active_slot_spans_head"]
        for i, x in enumerate(buckets):
            lst = [x["active_slot_spans_head"], x["empty_slot_spans_head"], x["decommitted_slot_spans_head"]]
            slots_chk = sum(lst)

            output_bucket_head = f"{space}PartitionBucket [0x{i:x}] slot_size: 0x{x['slot_size']:x}, @0x{x['address']:x}" +\
                f"(num_system_pages_per_slot_span: 0x{x['num_system_pages_per_slot_span']:x}, " +\
                f"num_full_slot_spans: 0x{x['num_full_slot_spans']:x}, " +\
                f"slot_size_reciprocal: 0x{x['slot_size_reciprocal']:x})"

            output_bucket_body = f"{space}{space}active_slot_spans_head = 0x{x['active_slot_spans_head']:x}, " +\
                f"empty_slot_spans_head = 0x{x['empty_slot_spans_head']:x}, " +\
                f"decommitted_slot_spans_head: 0x{x['decommitted_slot_spans_head']:x}"

            buckets_address.append((x['address'], x['active_slot_spans_head']))

            if slots_chk:
                if sentinel_slot_span in lst:
                    output_bucket_body += " [!] points to sentinel_slot_span"
                str_buckets_.append(output_bucket_head + "\n" + output_bucket_body + "\n")
            else:
                str_buckets_.append(f"[!] Empty PartitionBucket@0x{x['address']:x} [0x{i:x}] slot_size: 0x{x['slot_size']:x}")

        if dump_only_buckets:
            return buckets_address, sentinel_bucket, str_buckets_

        str_.append(f"\nSentinel_bucket:\n" + print_dict(sentinel_bucket))
        str_ += str_buckets_
        print("\n".join(str_))


    def dump_bucket(self, addr):
        partition_bucket_ptr = addr
        prev_partition_bucket_ptr = partition_bucket_ptr - partition_bucket_size
        next_partition_bucket_ptr = partition_bucket_ptr + partition_bucket_size
        partition_bucket = self.read_bucket(addr)[0]
        str_ = [
            f"PartitionBucket address: 0x{partition_bucket_ptr:x} (prev: 0x{prev_partition_bucket_ptr:x}, next: 0x{next_partition_bucket_ptr:x})",
            print_dict(partition_bucket),
        ]
        print("\n".join(str_))


    def dump_slotspan_meta(self, addr, traverse_slot_spans=False, do_print=True):
        metadata_current_page_ptr = addr
        prev_metadata_partpage_ptr = metadata_current_page_ptr - sz_partitionpage_metadata
        next_metadata_partpage_ptr = metadata_current_page_ptr + sz_partitionpage_metadata
        metadata_current_page = self.read_partitionpage_metadata(metadata_current_page_ptr)[0]
        str_ = [
            f"PartitionPage (SlotSpanMetadata) address per index: 0x{metadata_current_page_ptr:x} (previous: 0x{prev_metadata_partpage_ptr:x}, next: 0x{next_metadata_partpage_ptr:x})",
            print_dict(metadata_current_page),
        ]

        freelist_tmp = self.dump_freelist(metadata_current_page['freelist_head'], do_print=False)
        str_.append(freelist_tmp)
        if traverse_slot_spans:
            next_slot_span = metadata_current_page['next_slot_span']
            if next_slot_span:
                str_.append("")
                str_ += self.dump_slotspan_meta(next_slot_span, traverse_slot_spans=True, do_print=False)

        if do_print:
            print("\n".join(str_))
        return str_


    def pp_freelist(self, freelist_):
        str_ = [f"Freelist ({len(freelist_)})"]
        if freelist_:
            head_ = freelist_[0]
            tail_ = freelist_[1:]
            if pa_PrintMetadataPage.limit_output_freelist == 0:
                pass
            else:
                str_.append(f"{space}0x{head_:x} ->")
                if pa_PrintMetadataPage.limit_output_freelist > 0:
                    if pa_PrintMetadataPage.limit_output_freelist < len(tail_):
                        tail_ = tail_[-1 * pa_PrintMetadataPage.limit_output_freelist:]
                        str_.append(f"{space}{'...'.rjust(14,' ')} ->")
                for x in tail_:
                    str_.append(f"{space}0x{x:x} ->")
        else :
            str_.append(f"[!] freelist is empty")
        #
        return str_


    def dump_freelist(self, addr, do_print=True):
        freelist_ = self.read_partition_freelist_entry(addr)
        str_ = self.pp_freelist(freelist_)
        str_ = "\n".join(str_)
        if do_print:
            print(str_)
        return str_
 

    def dump_thread_bucket(self, addr, do_print=True):
        current, bucket_ = self.read_thread_bucket(addr)
        x = bucket_
        freelist_head = x['freelist_head']
        str_ = [
            f"Bucket slot_size: {hex(x['slot_size']).rjust(6,' ')}, freelist_head: {hex(freelist_head).rjust(14,' ')} (count: {x['count']})  stored at 0x{addr:x}",
        ]
        if freelist_head:
            old_limit_output_freelist = pa_PrintMetadataPage.limit_output_freelist
            pa_PrintMetadataPage.limit_output_freelist = -1
            str_.append(self.dump_freelist(freelist_head, do_print=False))
            pa_PrintMetadataPage.limit_output_freelist = old_limit_output_freelist
        else :
            str_.append(f"{space}freelist is empty")
        if do_print:
            print("\n".join(str_))
        return str_


    def dump_thread_cache(self, addr, is_page=False):

        if is_page:
            thread_cache = self.get_thread_cache_candidates()
            if not thread_cache:
                thread_cache = self.read_info(addr, return_thread_cache_list=True)
            if thread_cache:
                addr = thread_cache[0]
            else:
                print("[x] Can't find thread cache address")
                return
 
        current, (_thread_cache, _thread_cache_stats, _thread_cache_alloc_stats, _buckets) = self.read_thread_cache(addr)
        str_ = [
            "",
            f"[Thread-cache: 0x{addr:x}]",
            print_key_value("cached_memory_", _thread_cache),
            print_key_value("should_purge_", _thread_cache),
            f"{space}stats_ \x7b",
            self.toString_ThreadCacheStats(_thread_cache_stats, space=space + (" " * 4)),
            f"{space}\x7d",
            f"{space}thread_alloc_stats_ \x7b",
            self.toString_ThreadAllocStats(_thread_cache_alloc_stats, space=space + (" " * 4)),
            f"{space}\x7d",
            "\n".join(f"{space}Bucket [{hex(i).rjust(4,' ')}] slot_size: {hex(x['slot_size']).rjust(6,' ')}, freelist_head: {hex(x['freelist_head']).rjust(14,' ')} (count: {x['count']})  stored at 0x{x['addr']:x}" for i,x in enumerate(_buckets)),
            print_key_value("root_", _thread_cache, hex_fmt=True),
            print_key_value("thread_id_",_thread_cache),
            print_key_value("next_",_thread_cache, hex_fmt=True),
            print_key_value("prev_",_thread_cache, hex_fmt=True),
 
        ]
        print("\n".join(str_))


    def get_super_page_list(self, addr, do_print=True):
        output = []
        output_str_ = []
        root_addr = self.read_info(addr, return_super_page_list=True)
        first_extent = 0
        if root_addr: 
            root_object, _, _, _, _ = self.read_root(root_addr)
            first_extent = root_object["first_extent"]
            if first_extent:
                output = self.read_SuperPageExtentEntry(first_extent)
                if output:
                    output_str_ = self.dump_super_pages(first_extent, super_page_list=output)
        if do_print:
            print("\n".join(output_str_))
        return output, output_str_


    def read_info(self, addr, return_super_page_list=False, return_thread_cache_list=False):
        str_ = []
        super_page = get_super_page(addr)
        partition_page_index = get_partition_page_index(addr)
        slot_span_start = get_slot_span_start(super_page, partition_page_index)
        adjacent_slot_span = slot_span_start + kPartitionPageSize
        #
        if partition_page_index >= (NumPartitionPagesPerSuperPage-1):
            str_.append(f"[!] invalid partiton page index '{partition_page_index}'")
            return str_
        # The metadata area is exactly one system page (the guard page) into the super page.
        metadata_start_ptr = super_page + SystemPageSize
        # p sizeof(*((partition_alloc::internal::PartitionPage<1> *) 0x200400a01e80))
        # $27 = 0x20
        metadata_current_page_ptr = metadata_start_ptr + (partition_page_index * sz_partitionpage_metadata)
        #
        prev_partition_page_index = partition_page_index - 1
        next_partition_page_index = partition_page_index + 1
        prev_metadata_partpage_ptr = metadata_current_page_ptr - sz_partitionpage_metadata
        next_metadata_partpage_ptr = metadata_current_page_ptr + sz_partitionpage_metadata
        #
        metadata_current_page = self.read_partitionpage_metadata(metadata_current_page_ptr)[0]
        partition_bucket_ptr = metadata_current_page ["bucket"]
        prev_partition_bucket_ptr = partition_bucket_ptr - partition_bucket_size
        next_partition_bucket_ptr = partition_bucket_ptr + partition_bucket_size
        partition_bucket = self.read_bucket(partition_bucket_ptr)[0]
        slot = metadata_current_page["freelist_head"]
        num_allocated_slots = metadata_current_page["num_allocated_slots"]
        extent_metadata = self.read_extent_metadata(addr)[0]
        root_addr = extent_metadata["root"]

        if return_super_page_list:
            return root_addr
        #

        thread_cache = self.get_thread_cache_candidates()

        if not self.skip_root:
            if not thread_cache and root_addr:
                root_object, _, _, _, _ = self.read_root(root_addr)
                first_extent = root_object["first_extent"]
                self.set_thread_cache_candidates(self.scan_for_thread_cache(root_addr, get_super_page(first_extent)))
                thread_cache = self.get_thread_cache_candidates()


        if return_thread_cache_list:
            return thread_cache

        str_ = [
            f"",
            f"[super_page: 0x{super_page:x}] (partitionpage/slot-span index: {partition_page_index})",
            f"PartitionSuperPageExtentEntry (which is the first PartitionPage metadata) at: 0x{metadata_start_ptr:x}",
            print_dict_2(extent_metadata),
            f"ThreadCache candidates: [{', '.join([hex(x) for x in thread_cache])}]",
            f"PartitionPage (SlotSpanMetadata) address per index: 0x{metadata_current_page_ptr:x} (previous: 0x{prev_metadata_partpage_ptr:x}, next: 0x{next_metadata_partpage_ptr:x})",
            print_dict(metadata_current_page),
        ]
        #
        if partition_bucket_ptr:
            slot_size = partition_bucket["slot_size"]
            num_of_slots = (kPartitionPageSize // slot_size) 
            last_slot_span = slot_span_start + ((num_of_slots - 1) * slot_size)
            slot_span_waste = adjacent_slot_span - (last_slot_span + slot_size)

            #
            #

            str_ += [
                f"slot_span (first, last):    0x{slot_span_start:x} 0x{last_slot_span:x}",
                f"adjacent slot span address: 0x{adjacent_slot_span:x}",
                f"slot size: 0x{slot_size:x}, total slots: 0x{num_of_slots:x} (allocated: 0x{num_allocated_slots:x}), bytes wasted: {slot_span_waste}",
                f"PartitionBucket address: 0x{partition_bucket_ptr:x} (prev: 0x{prev_partition_bucket_ptr:x}, next: 0x{next_partition_bucket_ptr:x})",
                print_dict(partition_bucket),
            ]
            #
            if slot:
                contiguous_slot_span_freelist = self.search_contiguous_slot_span(slot, slot_size)
                contiguous_slot_span = self.search_contiguous_slot_span(slot, slot_size, based_on_freelist_head=False)
                slot_chain = self.read_slot_chain(slot)
                slot_adjacent = slot + slot_size
                str_.append(f"Free Slot address:  0x{slot:x} " + "  --> " + " --> ".join([hex(x) for x in slot_chain]))
                str_.append(f"Slot adjacent: 0x{slot_adjacent:x}")
                if contiguous_slot_span_freelist :
                    str_.append("Contiguous free slots (based on freelist heads):\n" + "\n".join([f"{space}{x}" for x in contiguous_slot_span_freelist]))
                if contiguous_slot_span :
                    str_.append("Contiguous free slots:\n" + "\n".join([f"{space}{x}" for x in contiguous_slot_span]))
            else:
                str_.append(f"Free Slot address: 0x0  [!] freelist_head is empty")
            #
        else:
            str_.append(f"[!] PartititonBucket is null")

        self.print_previous_or_next_partpage(
            str_, 
            super_page, 
            slot_span_start, 
            prev_partition_page_index,
            prev_metadata_partpage_ptr,
        )
        #
        self.print_previous_or_next_partpage(
            str_, 
            super_page, 
            slot_span_start, 
            next_partition_page_index,
            next_metadata_partpage_ptr,
            previous=False,
        )
        #
        return str_


    def print_info(self, addr):
        str_ = self.read_info(addr)
        print("\n".join(str_))
        print("")
            

    def print_previous_or_next_partpage(self, 
            str_, 
            super_page, 
            slot_span_start, 
            prev_partition_page_index,
            prev_metadata_partpage_ptr,
            previous=True,
        ):
        prefix = "(prev)"
        if previous :
            # previous next partitionpage parsing
            if super_page + kPartitionPageSize == slot_span_start:
                str_.append("[!] Previous partition page is the guard page")
                return
            else:
                if prev_partition_page_index < 0:
                    str_.append("[!] No previous partition page (this should not happen)")
                    return
                if prev_partition_page_index == 0:
                    str_.append("[!] TODO: previous partitionpage index is 0, but first partitionpage metadata refers to an extent")
                    return
        else :
            prefix = "(next)"
            if prev_partition_page_index >= (NumPartitionPagesPerSuperPage-1):
                str_.append(f"[!] Next partiton page is the guard page")
                return

        prev_slot_span_start = get_slot_span_start(super_page, prev_partition_page_index)
        prev_super_page = get_super_page(prev_slot_span_start)
        if super_page != prev_super_page:
            str_.append(f"[!] Superpage is different (this should not happen)")
            return

        prev_metadata_partpage = self.read_partitionpage_metadata(prev_metadata_partpage_ptr)[0]
        prev_partition_bucket_ptr = prev_metadata_partpage["bucket"]
        str_.append(f"{prefix}partitionpage / slot-span index: {prev_partition_page_index}")
        str_.append(f"{prefix}PartitionPage (SlotSpanMetadata) address per index: 0x{prev_metadata_partpage_ptr:x}")

        if prev_partition_bucket_ptr == 0:
            str_.append(f"{prefix}slot_span: 0x{prev_slot_span_start:x}  [!] Partitionpage is a struct SubsequentPageMetadata, not supported parsing #TODO")
        else:
            prev_partition_bucket = self.read_bucket(prev_partition_bucket_ptr)[0]
            prev_slot = prev_metadata_partpage["freelist_head"]
            prev_slot_size = prev_partition_bucket["slot_size"]
            prev_num_allocated_slots = prev_metadata_partpage["num_allocated_slots"]
            prev_slot_chain = self.read_slot_chain(prev_slot, limit=-1, include_initial_slot=True)
            prev_num_of_slots = (kPartitionPageSize // prev_slot_size) 
            prev_last_slot_span = prev_slot_span_start + ((prev_num_of_slots - 1) * prev_slot_size)
            prev_adjacent_slot_span = prev_slot_span_start + kPartitionPageSize
            prev_slot_span_waste = prev_adjacent_slot_span - (prev_last_slot_span + prev_slot_size)
            str_.append(f"{prefix}slot_span (first, last):    0x{prev_slot_span_start:x} 0x{prev_last_slot_span:x}")
            str_.append(
                f"{prefix}slot size: 0x{prev_slot_size:x}, total slots: 0x{prev_num_of_slots:x} (allocated: 0x{prev_num_allocated_slots:x}), bytes wasted: {prev_slot_span_waste}"
            )
            str_.append(f"{prefix}Free Slot address:  " + " --> ".join([hex(x) for x in prev_slot_chain[:3]]))
            if prev_last_slot_span in prev_slot_chain:
                str_.append(f"{prefix}last_slot_span will be allocated in {prev_slot_chain.index(prev_last_slot_span)} steps")
            else:
                str_.append(f"{prefix}last_slot_span is not free")

            if prev_slot_span_start in prev_slot_chain:
                str_.append(f"{prefix}first_slot_span will be allocated in {prev_slot_chain.index(prev_slot_span_start)} steps")
            else:
                str_.append(f"{prefix}first_slot_span is not free")


    def read_slot_chain(self, addr, limit=3, include_initial_slot=False):
        slot_chain = [] if not include_initial_slot else [addr]
        current_addr = addr
        partition_page_index = get_partition_page_index(current_addr)
        while limit != 0:
            limit -= 1
            if current_addr == 0:
                break
            if partition_page_index != get_partition_page_index(current_addr):
                # jumped to a new partitionpage .. break
                break
            try:
                current_addr = self.read_long_from_memory_be(current_addr)
            except gdb.MemoryError as ex:
                print(f"[!] can't read an entry on the freelist_head field {hex(current_addr)}")
                break
            slot_chain.append(current_addr)
        return slot_chain


    def read_extent_metadata(self, addr):
        """
        struct PartitionSuperPageExtentEntry {
          PartitionRoot<thread_safe>* root;
          PartitionSuperPageExtentEntry<thread_safe>* next;
          uint16_t number_of_consecutive_super_pages;
          uint16_t number_of_nonempty_slot_spans;
        }
        """
        ptrsize = 8
        _extent = {}
        super_page = get_super_page(addr)
        current = super_page + SystemPageSize
        _extent["root"] = self.read_long_from_memory(current)
        current += ptrsize
        _extent["next"] = self.read_long_from_memory(current)
        _extent["number_of_consecutive_super_pages"] = self.read_short_from_memory(current)
        current += 2
        _extent["number_of_nonempty_slot_spans"] = self.read_short_from_memory(current)
        current += 2
        return _extent, current


    def read_partitionpage_metadata(self, addr):
        ptrsize = 8
        _slot_span = {}
        current = addr
        """
        https://source.chromium.org/chromium/chromium/src/+/main:base/allocator/partition_allocator/partition_page.h
        struct SlotSpanMetadata {
          PartitionFreelistEntry* freelist_head = nullptr;
          SlotSpanMetadata<thread_safe>* next_slot_span = nullptr;
          PartitionBucket<thread_safe>* const bucket = nullptr;
          uint32_t marked_full : 1
          uint32_t num_allocated_slots : kMaxSlotsPerSlotSpanBits; // 13 bits
          uint32_t num_unprovisioned_slots : kMaxSlotsPerSlotSpanBits; // 13 bits
          const uint32_t can_store_raw_size_ : 1;
          uint32_t freelist_is_sorted_ : 1;
          uint32_t unused1_ : (32 - 1 - 2 * kMaxSlotsPerSlotSpanBits - 1 - 1); // 3 bits
          uint16_t in_empty_cache_ : 1;
          uint16_t empty_cache_index_ : kEmptyCacheIndexBits; // 7 bits
          uint16_t unused2_ : (16 - 1 - kEmptyCacheIndexBits); // 8 bits
        }
        """
        if not current:
            return _slot_span, current
        _slot_span["freelist_head"] = self.read_long_from_memory(current)
        current += ptrsize
        _slot_span["next_slot_span"] = self.read_long_from_memory(current)
        current += ptrsize
        _slot_span["bucket"] = self.read_long_from_memory(current)
        current += ptrsize
        x = self.read_int_from_memory(current)
        current += 4
        _slot_span["marked_full"] = (x >> 0) & 1
        _slot_span["num_allocated_slots"] = (x >> 1) & 0x1fff
        _slot_span["num_unprovisioned_slots"] = (x >> 14) & 0x1fff
        _slot_span["can_store_raw_size_"] = (x >> 27) & 1
        _slot_span["freelist_is_sorted_"] = (x >> 28) & 1
        _slot_span["unused1_"] = (x >> 29) & 0x7
        x = self.read_short_from_memory(current)
        current += 2
        _slot_span["in_empty_cache_"] = (x >> 0) & 1
        _slot_span["empty_cache_index_"] = (x >> 1) & 0x7f
        _slot_span["unused2_"] = (x >> 8) & 0xff
        return _slot_span, current


    def read_bucket(self, addr, store_address=False):
        ptrsize = 8
        _bucket = {}
        current = addr
        """
        https://source.chromium.org/chromium/chromium/src/+/main:base/allocator/partition_allocator/partition_bucket.h
        struct base::internal::PartitionBucket {
            SlotSpanMetadata<thread_safe>* active_slot_spans_head;
            SlotSpanMetadata<thread_safe>* empty_slot_spans_head;
            SlotSpanMetadata<thread_safe>* decommitted_slot_spans_head;
            uint32_t slot_size;
            uint32_t num_system_pages_per_slot_span : 8;
            uint32_t num_full_slot_spans : 24;
            uint64_t slot_size_reciprocal;
        };
        """
        if not current:
            return _bucket, current
        if store_address:
            _bucket["address"] = addr
        _bucket["active_slot_spans_head"] = self.read_long_from_memory(current)
        current += ptrsize
        _bucket["empty_slot_spans_head"] = self.read_long_from_memory(current)
        current += ptrsize
        _bucket["decommitted_slot_spans_head"] = self.read_long_from_memory(current)
        current += ptrsize
        _bucket["slot_size"] = self.read_int_from_memory(current)
        current += 4
        x = self.read_int_from_memory(current)
        _bucket["num_system_pages_per_slot_span"] = x & 0xff
        _bucket["num_full_slot_spans"] = (x >> 8) & 0xffffff
        current += 4
        _bucket["slot_size_reciprocal"] = self.read_long_from_memory(current)
        current += 8
        return _bucket, current


    def search_contiguous_slot_span(self, freelist_head, slot_size, based_on_freelist_head=True):
        """
            We list slots spans that are contiguous by traversing the
            freelist_head chain. 
            (default: traverse freelist, otherwise list them based on address order)

        """
        slot_chain = self.read_slot_chain(freelist_head, limit=-1)
        head = slot_chain.pop(0)
        tail = slot_chain
        contiguous = [[]]

        if not based_on_freelist_head:
            slot_chain = sorted(slot_chain)

        for x in tail:
            if head + slot_size == x:
                if not contiguous[-1]:
                    contiguous[-1].append(head)
                contiguous[-1].append(x)
            else:
                if contiguous[-1]:
                    contiguous.append([])
            head = x
        output = []
        for x in contiguous:
            if x :
                output.append(f"0x{x[0]:x} ... 0x{x[-1]:x} [# slots: {len(x)}]")
        return output


    def read_root(self, addr):
        ptrsize = 8
        _root = {}
        current = addr
        """
        https://source.chromium.org/chromium/chromium/src/+/main:base/allocator/partition_allocator/partition_root.h
        struct base::PartitionRoot {
            union {
                struct Flags {
                    QuarantineMode quarantine_mode; // uint8_t
                    ScanMode scan_mode;             // uint8_t
                    BucketDistribution bucket_distribution = BucketDistribution::kCoarser; // uint8_t
                    bool with_thread_cache = false;
                    bool allow_aligned_alloc;
                    bool allow_cookie;
                    bool brp_enabled_;
                    bool brp_zapping_enabled_;
                    //bool mac11_malloc_size_hack_enabled_ = false;
                    bool use_configurable_pool;
                    //int pkey;
                    //uint32_t extras_size;
                    //uint32_t extras_offset;
                }
                uint8_t one_cacheline[internal::kPartitionCachelineSize]; // 64 bytes
            }
            ::partition_alloc::Lock lock_;  // 8 bytes
            Bucket buckets[internal::kNumBuckets] = {};
            Bucket sentinel_bucket{};
            bool initialized = false;
            std::atomic<size_t> total_size_of_committed_pages{0};
            std::atomic<size_t> max_size_of_committed_pages{0};
            std::atomic<size_t> total_size_of_super_pages{0};
            std::atomic<size_t> total_size_of_direct_mapped_pages{0};
            size_t total_size_of_allocated_bytes PA_GUARDED_BY(lock_) = 0;
            size_t max_size_of_allocated_bytes PA_GUARDED_BY(lock_) = 0;
            std::atomic<uint64_t> syscall_count{};
            std::atomic<uint64_t> syscall_total_time_ns{};
            std::atomic<size_t> total_size_of_brp_quarantined_bytes{0};
            std::atomic<size_t> total_count_of_brp_quarantined_slots{0};
            std::atomic<size_t> cumulative_size_of_brp_quarantined_bytes{0};
            std::atomic<size_t> cumulative_count_of_brp_quarantined_slots{0};
            size_t empty_slot_spans_dirty_bytes PA_GUARDED_BY(lock_) = 0;
            int max_empty_slot_spans_dirty_bytes_shift = 3;
            uintptr_t next_super_page = 0;
            uintptr_t next_partition_page = 0;
            uintptr_t next_partition_page_end = 0;
            SuperPageExtentEntry* current_extent = nullptr;
            SuperPageExtentEntry* first_extent = nullptr;
            DirectMapExtent* direct_map_list PA_GUARDED_BY(lock_) = nullptr;
            SlotSpan* global_empty_slot_span_ring[internal::kMaxFreeableSpans] PA_GUARDED_BY(lock_) = {};
            int16_t global_empty_slot_span_ring_index PA_GUARDED_BY(lock_) = 0;
            int16_t global_empty_slot_span_ring_size PA_GUARDED_BY(lock_) = internal::kDefaultEmptySlotSpanRingSize;
            uintptr_t inverted_self = 0;
            std::atomic<int> thread_caches_being_constructed_{0};
            bool quarantine_always_for_testing = false;
            PartitionRoot* next_root;
            PartitionRoot* prev_root;
        }
        """
        f1 = lambda x, i: (x >> (i*8)) & 0xff
        _flags = {}
        x = self.read_long_from_memory(current)
        _flags["quarantine_mode"] = f1(x, 0)
        _flags["scan_mode"] = f1(x, 1)
        _flags["bucket_distribution"] = f1(x, 2)
        _flags["with_thread_cache"] = f1(x, 3)
        _flags["allow_aligned_alloc"] = f1(x, 4)
        _flags["allow_cookie"] = f1(x, 5)
        _flags["brp_enabled_"] = f1(x, 6)
        _flags["brp_zapping_enabled_"] = f1(x, 7)
        current += ptrsize
        x = self.read_int_from_memory(current)
        _flags["use_configurable_pool"] = f1(x, 0)
        current += 4
        _flags["pkey"] = self.read_int_from_memory(current)
        current += 4
        _flags["extras_size"] = self.read_int_from_memory(current)
        current += 4
        _flags["extras_offset"] = self.read_int_from_memory(current)
        current += 4 + 40
        _flags["quarantine_mode"] = root_QuarantineMode[_flags["quarantine_mode"]] + f" ({_flags['quarantine_mode']})"
        _flags["scan_mode"] = root_ScanMode[_flags["scan_mode"]] + f" ({_flags['scan_mode']})"
        _flags["bucket_distribution"] = root_BucketDistribution[_flags["bucket_distribution"]] + f" ({_flags['bucket_distribution']})"

        _root["lock_"] = self.read_long_from_memory(current)
        current += 8
        _buckets = []
        while True:
            if self.read_long_from_memory(current) == 1: # search `bool initialized`
                break
            bucket, current = self.read_bucket(current, store_address=True)
            _buckets.append(bucket)

        _sentinel_bucket = _buckets.pop()
        #
        _root["initialized"] = self.read_long_from_memory(current) & 0xff
        current += ptrsize # with pad
        _root["total_size_of_committed_pages"] = self.read_long_from_memory(current)
        current += ptrsize
        _root["max_size_of_committed_pages"] = self.read_long_from_memory(current)
        current += ptrsize
        _root["total_size_of_super_pages"] = self.read_long_from_memory(current)
        current += ptrsize
        _root["total_size_of_direct_mapped_pages"] = self.read_long_from_memory(current)
        current += ptrsize
        _root["total_size_of_allocated_bytes"] = self.read_long_from_memory(current)
        current += ptrsize
        _root["max_size_of_allocated_bytes"] = self.read_long_from_memory(current)
        current += ptrsize
        _root["syscall_count"] = self.read_long_from_memory(current)
        current += ptrsize
        _root["syscall_total_time_ns"] = self.read_long_from_memory(current)
        current += ptrsize
        _root["total_size_of_brp_quarantined_bytes"] = self.read_long_from_memory(current)
        current += ptrsize
        _root["total_count_of_brp_quarantined_slots"] = self.read_long_from_memory(current)
        current += ptrsize
        _root["cumulative_size_of_brp_quarantined_bytes"] = self.read_long_from_memory(current)
        current += ptrsize
        _root["cumulative_count_of_brp_quarantined_slots"] = self.read_long_from_memory(current)
        current += ptrsize
        _root["empty_slot_spans_dirty_bytes"] = self.read_int_from_memory(current)
        current += ptrsize # with pad
        _root["max_empty_slot_spans_dirty_bytes_shift"] = self.read_int_from_memory(current)
        current += ptrsize # with pad
        #
        _root["next_super_page"] = self.read_long_from_memory(current)
        current += ptrsize
        _root["next_partition_page"] = self.read_long_from_memory(current)
        current += ptrsize
        _root["next_partition_page_end"] = self.read_long_from_memory(current)
        current += ptrsize
        _root["current_extent"] = self.read_long_from_memory(current)
        current += ptrsize
        _root["first_extent"] = self.read_long_from_memory(current)
        current += ptrsize
        _root["direct_map_list"] = self.read_long_from_memory(current)
        current += ptrsize

        _global_empty_slot_span_ring = []
        inv = addr ^ ((1 << (ptrsize * 8)) - 1)

        while True:
            if self.read_long_from_memory(current + ptrsize) == inv: # search `inverted_self`
                break
            x = self.read_long_from_memory(current)
            current += ptrsize
            _global_empty_slot_span_ring.append(hex(x))
        _root["global_empty_slot_span_ring_index"] = self.read_short_from_memory(current)
        current += 2
        _root["global_empty_slot_span_ring_size"] = self.read_short_from_memory(current)
        current += ptrsize - 2 # with pad
        _root["inverted_self"] = self.read_long_from_memory(current)
        current += ptrsize
        _root["thread_caches_being_constructed_"] = self.read_int_from_memory(current)
        current += 4
        _root["quarantine_always_for_testing"] = self.read_int_from_memory(current) & 0xff
        current += 4
        _root["next_root"] = self.read_long_from_memory(current)
        current += ptrsize
        _root["prev_root"] = self.read_long_from_memory(current)
        current += ptrsize
        return _root, _buckets, _sentinel_bucket, _global_empty_slot_span_ring, _flags


    def read_SuperPageExtentEntry(self, addr, recursive=True):
        ptrsize = 8
        current = addr
        output = []
        """
            SuperPageExtentEntry {
                PartitionRoot root;
                PartitionSuperPageExtentEntry * next;
                uint16_t number_of_consecutive_super_pages;
                uint16_t number_of_nonempty_slot_spans;
            }
        """
        while current:
            _extent = {}
            _extent["addr"] = current
            _extent["root"] = self.read_long_from_memory(current)
            current += ptrsize
            _extent["next"] = self.read_long_from_memory(current)
            current += ptrsize
            _extent["number_of_consecutive_super_pages"] = self.read_short_from_memory(current)
            current += 2
            _extent["number_of_nonempty_slot_spans"] = self.read_short_from_memory(current)
            output.append(_extent)
            current = _extent["next"]
            if not recursive:
                break
        return output



    def toString_ThreadCacheStats(self, obj, space=space):
        str_in_order = [
            print_key_value("alloc_count", obj, space),
            print_key_value("alloc_hits", obj, space),
            print_key_value("alloc_misses", obj, space),
            print_key_value("alloc_miss_empty", obj, space),
            print_key_value("alloc_miss_too_large", obj, space),
            print_key_value("cache_fill_count", obj, space),
            print_key_value("cache_fill_hits", obj, space),
            print_key_value("cache_fill_misses", obj, space),
            print_key_value("batch_fill_count", obj, space),
            print_key_value("bucket_total_memory", obj, space),
            print_key_value("metadata_overhead", obj, space),
            print_index_per_value("allocs_per_bucket_", obj,  space=space),
        ]
        return "\n".join(str_in_order)


    def read_ThreadCacheStats(self, addr, kNumBuckets=128):
        ptrsize = 8
        _thread_cache_stats = {}
        current = addr
        """
            struct ThreadCacheStats {
              uint64_t alloc_count;   // Total allocation requests.
              uint64_t alloc_hits;    // Thread cache hits.
              uint64_t alloc_misses;  // Thread cache misses.
              // Allocation failure details:
              uint64_t alloc_miss_empty;
              uint64_t alloc_miss_too_large;
              // Cache fill details:
              uint64_t cache_fill_count;
              uint64_t cache_fill_hits;
              uint64_t cache_fill_misses;  // Object too large.
              uint64_t batch_fill_count;  // Number of central allocator requests.
              // Memory cost:
              uint32_t bucket_total_memory;
              uint32_t metadata_overhead;
              uint64_t allocs_per_bucket_[internal::kNumBuckets + 1];
            };
        """
        _thread_cache_stats["alloc_count"] = self.read_long_from_memory(current)
        current += ptrsize
        _thread_cache_stats["alloc_hits"] = self.read_long_from_memory(current)
        current += ptrsize
        _thread_cache_stats["alloc_misses"] = self.read_long_from_memory(current)
        current += ptrsize
        _thread_cache_stats["alloc_miss_empty"] = self.read_long_from_memory(current)
        current += ptrsize
        _thread_cache_stats["alloc_miss_too_large"] = self.read_long_from_memory(current)
        current += ptrsize
        _thread_cache_stats["cache_fill_count"] = self.read_long_from_memory(current);
        current += ptrsize
        _thread_cache_stats["cache_fill_hits"] = self.read_long_from_memory(current)
        current += ptrsize
        _thread_cache_stats["cache_fill_misses"] = self.read_long_from_memory(current)
        current += ptrsize
        _thread_cache_stats["batch_fill_count"] = self.read_long_from_memory(current)
        current += ptrsize
        _thread_cache_stats["bucket_total_memory"] = self.read_int_from_memory(current)
        current += 4
        _thread_cache_stats["metadata_overhead"] = self.read_int_from_memory(current)
        current += 4
        _thread_cache_stats["allocs_per_bucket_"] = []
        for _ in range(kNumBuckets + 1):
            _thread_cache_stats["allocs_per_bucket_"].append(self.read_long_from_memory(current))
            current += ptrsize
        return current, _thread_cache_stats


    def toString_ThreadAllocStats(self, obj, space=space):
        return print_keys_values(obj, space)


    def read_ThreadAllocStats(self, addr):
        ptrsize = 8
        _thread_cache_alloc_stats = {}
        current = addr
        """
            struct ThreadAllocStats {
              uint64_t alloc_count;
              uint64_t alloc_total_size;
              uint64_t dealloc_count;
              uint64_t dealloc_total_size;
            };
        """
        _thread_cache_alloc_stats["alloc_count"] = self.read_long_from_memory(current)
        current += ptrsize
        _thread_cache_alloc_stats["alloc_total_size"] = self.read_long_from_memory(current)
        current += ptrsize
        _thread_cache_alloc_stats["dealloc_count"] = self.read_long_from_memory(current) 
        current += ptrsize
        _thread_cache_alloc_stats["dealloc_total_size"] = self.read_long_from_memory(current)
        current += ptrsize
        return current, _thread_cache_alloc_stats
 
    def read_partition_freelist_entry(self, addr):
        ptrsize = 8
        _freelist = []
        current = addr
        """
            class PartitionFreelistEntry {
             private:
              constexpr explicit PartitionFreelistEntry(std::nullptr_t)
                  : encoded_next_(EncodedPartitionFreelistEntryPtr(nullptr))
        """
        while current:
            # clean first 2 bytes, since sometimes it is set to 0x1000, don't know why maybe it's some kind of memory tag
            current &= kPageMask_custom
            _freelist.append(current)
            current = self.read_long_from_memory_be(current)
        return _freelist


    def read_thread_bucket(self, addr):
        ptrsize = 8
        _bucket = {}
        current = addr
        """
            struct Bucket {     
                internal::PartitionFreelistEntry* freelist_head = nullptr;
                // Want to keep sizeof(Bucket) small, using small types.
                uint8_t count = 0;
                std::atomic<uint8_t> limit{};  // Can be changed from another thread.
                uint16_t slot_size = 0;
            };
        """
        _bucket["addr"] = addr
        _bucket["freelist_head"] = self.read_long_from_memory(current)
        current += ptrsize
        x = self.read_short_from_memory(current)
        _bucket["count"] = x & 0xff
        _bucket["limit"] = (x >> 8) & 0xff
        current += 2
        _bucket["slot_size"] = self.read_short_from_memory(current)
        current += 6 # +4 pad
        return current, _bucket


    def read_thread_buckets(self, addr, kBucketCount=72):
        ptrsize = 8
        _buckets = []
        current = addr
        for _ in range(kBucketCount):
            current, _bucket = self.read_thread_bucket(current)
            _buckets.append(_bucket)
        return current, _buckets


    def read_thread_cache(self, addr, kNumBuckets=128, kBucketCount=72, slot_size=0xa00):
        ptrsize = 8
        _thread_cache = {}
        current = addr
        """
            // base/allocator/partition_allocator/partition_stats.h
            class ThreadCache {
                uint32_t cached_memory_ = 0;
                std::atomic<bool> should_purge_;
                ThreadCacheStats stats_;
                ThreadAllocStats thread_alloc_stats_;
                
                // Buckets are quite big, though each is only 2 pointers.
                Bucket buckets_[kBucketCount];
                
                // Cold data below.
                PartitionRoot<>* const root_;
                PlatformThreadId thread_id_;
                ThreadCache * next_;
                ThreadCache * prev_;
            }
        """
        _thread_cache["cached_memory_"] = self.read_int_from_memory(current)
        current += 4
        _thread_cache["should_purge_"] = self.read_int_from_memory(current)
        current += 4
        current, _thread_cache_stats = self.read_ThreadCacheStats(current, kNumBuckets=kNumBuckets)
        current, _thread_cache_alloc_stats = self.read_ThreadAllocStats(current)
        current, _buckets = self.read_thread_buckets(current, kBucketCount=kBucketCount)
        _thread_cache["root_"] = self.read_long_from_memory(current)
        current += ptrsize
        _thread_cache["thread_id_"] = self.read_long_from_memory(current)
        current += ptrsize
        _thread_cache["next_"] = self.read_long_from_memory(current)
        current += ptrsize
        _thread_cache["prev_"] = self.read_long_from_memory(current)
        current += ptrsize
        return current, (_thread_cache, _thread_cache_stats, _thread_cache_alloc_stats, _buckets)


    def scan_for_thread_cache(self, root_addr, super_page, kNumBuckets=128, kBucketCount=72, slot_size=0xa00):
        """
        Scan memory for thread cacache candidates

            // thread cache is stored in the first super page, 
            // so we scan in slot spans having slot_size 0xa00 to find the root address
            //
            // kBucketCount: bucket entries fixed to 72, but it can vary

            |           struct | size                         |
            |------------------|------------------------------|
            | ThreadCacheStats | 0x50 + ((kNumBuckets+1)*0x8) |
            | ThreadAllocStats | 0x20                         |
            | bucket           | 0x10                         |

            thread cache    = 0x8 + 0x50 + ((kNumBuckets+1)*0x8) + 0x20 + (kBucketCount*0x10) + 0x20
                            = 0x98 + (kBucketCount*0x10) + ((kNumBuckets+1)*0x8)
                            = 0x920 // in our scenario

            so root will be stored at:
            * root          = 0x8 + 0x50 + ((kNumBuckets+1)*0x8) + 0x20 + (kBucketCount*0x10) 
                            = 0x900 // in our scenario

            We also need checking the field 'thread_id_' which in linux stores TID

        """

        ptrsize = 8
        _thread_cache = []
        if self.skip_tcache :
            return _thread_cache

        root_ptr_offset = 0x8 + 0x50 + ((kNumBuckets+1)*0x8) + 0x20 + (kBucketCount*0x10) 
        metadata_start_ptr = super_page + SystemPageSize
        partitionpages_start = super_page + kPartitionPageSize
        slot_span_indexes = {}

        #extent_metadata = metadata_start_ptr + sz_partitionpage_metadata
        #first_slot_span_metadata = extent_metadata + sz_partitionpage_metadata

        prev_bucket = 0
        for index in range(1,127):
            slot_span_metadata_ptr = metadata_start_ptr + (sz_partitionpage_metadata*index)
            slot_span_metadata = self.read_partitionpage_metadata(slot_span_metadata_ptr)[0]
            bucket_ptr = slot_span_metadata["bucket"]

            if bucket_ptr == 0:
                bucket_ptr = prev_bucket

            if bucket_ptr:
                # check slot_size
                bucket = self.read_bucket(bucket_ptr)[0]
                bucket_slot_size = bucket["slot_size"]
                if slot_size == bucket_slot_size:
                    slot_span_start = get_slot_span_start(super_page, index)
                    slot_span_indexes[index] = slot_span_start
            prev_bucket = bucket_ptr

        find_start_ = super_page + kPartitionPageSize
        find_length = kSuperPageSize - (kPartitionPageSize*2)
        find_string = f"(unsigned long long) 0x{root_addr:x}"
        find_cmd = f"find 0x{find_start_:x}, +0x{find_length:x}, {find_string}"
        find_result = gdb.execute(find_cmd, to_string=True)
        # manage gef alias
        if "usage: search-pattern" in find_result:
            find_string = "0x" + hex(root_addr)[2:].rjust(16, "0")
            find_cmd = f"search-pattern {find_string} 0x{find_start_:x} +0x{find_length:x}"
            find_result = gdb.execute(find_cmd, to_string=True)

        if "Pattern not found" not in find_result:
            for x in find_result.split("\n"):
                x = x.strip().split(" -")[0] # need split cause of gef's output be like: 0x277... - 0x277...  ->   "\x80\x9a\x24\x07\xd1\x5e\x00\x00"
                if x.startswith("0x"):
                    find_now = int(x, 16)
                    candidate_thread_cache = find_now - root_ptr_offset
                    find_page_index = get_partition_page_index(candidate_thread_cache)

                    if find_page_index in slot_span_indexes:
                        slot_span_start = slot_span_indexes[find_page_index]
                        if (candidate_thread_cache-slot_span_start) % slot_size == 0:
                            # found a candidate
                            _thread_cache.append(candidate_thread_cache)

        #to slow
        #if slot_span_list:
        #    for slot_span_start in slot_span_list:
        #        current = slot_span_start
        #        slot_span_end = slot_span_start + kPartitionPageSize
        #        while current < slot_span_end and not _thread_cache:
        #            root_ptr = current + root_ptr_offset
        #            root_ = self.read_long_from_memory(root_ptr)
        #            if root_ == root_addr:
        #                _thread_cache = current

        #        if _thread_cache :
        #            break
        #        current += kPartitionPageSize

        #print(f"[x] couldn't find any slot_span having slot size 0x{slot_size:x} .. this should not happen")
        return _thread_cache


class pa_Search(gdb.Command):
    """
        Search on partitionalloc space
    """

    def __init__(self):
        super().__init__("pa_search", gdb.COMMAND_USER)


    def int(self, target, conv=10):
        addr = None
        target = target.strip().lower()
        try:
            if target.startswith('0x'):
                addr = int(target, conv)
            else:
                addr = int(gdb.parse_and_eval(target))
        except Exception as ex:
            print(f"[x] Can't parse integer/symbol '{target}' exception: {ex}")
        return addr


    def usage(self):
        print(
            """Usage: pa_search [options] <address> "<hex>"

                    <address> : an address being part of PartitionAlloc memory space 

            options:
                --help : this message
                --print_at_offset <int> : for each match print a quad-word at specified offset
                --word_size <0|1|2|4>   : size of word to print (default value is 4 which translates to print a quad-word)
                --repeat <int> : print more than one quad-words at specified offset (default: 1)


            example: pa_search 0x200056a00 "41 41 41 41 41 00" 
            example: pa_search --print_at_offset -0x10 --repeat 2 0x200056a00 "41 41 41 00" 

            """
        )



    def invoke(self, arg, from_tty):
        args = gdb.string_to_argv(arg)
        print_help = False
        repeat_ = 1
        word_size = 4
        word_sizes = [0,1,2,4]
        print_at_offset = 0

        while args and args[0].startswith('--'):
            if args[0] == '--help' :
                print_help = True
                break
            elif args[0] == '--repeat' and len(args) >= 2:
                repeat_ = self.int(args[1], 16)
                args = args[2:]
            elif args[0] == '--print_at_offset' and len(args) >= 2:
                print_at_offset = self.int(args[1], 16)
                args = args[2:]
            elif args[0] == '--word_size' and len(args) >= 2:
                word_size = self.int(args[1], 16)
                args = args[2:]
                if word_size not in word_sizes:
                    print("[!] invalid word_size argument given, it should be 0,1,2, or 4 (default value)")
                    print_help = True
                    break
            else:
                print(f"Unknown option {args[0]}")
                print_help = True
                break

        # Validate remaining arguments
        if len(args) != 2:
            print_help = True

        if print_help :
            self.usage()
            return

        addr = self.int(args[0], 16)
        find_ = args[1]
        find_chars = ''.join(chr(int(x, 16)) for x in find_.split())

        pa_meta = pa_PrintMetadataPage()
        pa_meta.inferior = gdb.selected_inferior()
        super_page_list, super_page_str = pa_meta.get_super_page_list(addr, do_print=False)

        if not super_page_list:
            print("[X] couldn't find super page list .. this should not happen")
            return

        first_page = super_page_list[0]
        last_page = super_page_list[-1]
        last_num_consec = last_page['number_of_consecutive_super_pages']
        from_addr = (first_page["addr"] & kSuperPageBaseMask) + kPartitionPageSize
        to_addr = ((last_page["addr"] & kSuperPageBaseMask) + (last_num_consec * kSuperPageSize)) - kPartitionPageSize
        addr_per_super_page = {x["addr"] & kSuperPageBaseMask:[] for x in super_page_list}
        error_super_pages = []

        cmd = f"search-pattern --hex \"{find_}\" 0x{from_addr:x}-0x{to_addr:x}"
        is_not_gef = False
        output = ""

        try:
            output = gdb.execute(cmd, to_string=True)
        except gdb.error as ex:
            if "Undefined command" in str(ex):
                is_not_gef = True
            else :
                raise ex

        if "Undefined command" in output:
            is_not_gef = True

        if is_not_gef:
            # is not gef, then use find
            print("[!] gef's 'search-pattern' command is missing, we will find slightly less results, don't know why")
            cmd = f"find 0x{from_addr:x}, 0x{to_addr:x}," + repr(find_chars).replace("'",'"')
            output = gdb.execute(cmd, to_string=True)

        addr_list = []
        for x in output.split("\n")[1:] :
            if x.strip().startswith("0x") :
                addr_ = int(x.split("->")[0].split('-')[0].strip(), 16)
                addr_tmp = int(x.split("->")[0].split('-')[0].strip(), 16) & kSuperPageBaseMask
                if addr_tmp not in addr_per_super_page:
                    error_super_pages.append(f"[!] Can't find superpage per entry: {x}")
                else:
                    addr_per_super_page[addr_tmp].append(x)
                    addr_list.append(addr_)


        print("\n".join(super_page_str))
        if error_super_pages:
            print("\n".join(error_super_pages))

        total_matching_addresses = len(error_super_pages)
        for super_page_addr, findings_per_super_page in addr_per_super_page.items():
            if findings_per_super_page:
                total_matching_addresses += len(findings_per_super_page)
                print(f"0x{super_page_addr:x} found {len(findings_per_super_page)} matching addresses:")
                print("\n".join(findings_per_super_page))

        print(f"Total {total_matching_addresses} matching addresses")

        if print_at_offset:
            addr_list.sort()
            offsets = self.print_offsets(addr_list, print_at_offset, word_size, repeat_)
            print("Content at offset:")
            print("\n".join(offsets))


    def print_offsets(self, addrs, offset_, word_size, repeat_) :
        words_ = ["bx","hx", "wx", None, "gx"]
        word_ = words_[word_size]
        output = []
        for addr in addrs:
            addr_2 = addr + offset_
            cmd_ = f"x/{repeat_}{word_} 0x{addr_2:x}"
            output.append(hex(addr) + "\n" + gdb.execute(cmd_, to_string=True).strip() + "\n")
        return output





class pa_Collect_address(gdb.Command):
    """
        this was partially generated with gpt
    """

    def __init__(self):
        super().__init__("pa_collect_address", gdb.COMMAND_USER)


    def print_help(self):
        output = [
            "Usage: pa_collect_address [options] <breakpoint_location> <target> [<targets...>]" ,
            "   options:",
            "   --help  : this message",
            "   --thread <thread_number>                : execute command only the specified thread number",
            "   --start_at <breakpoint_location_start]  : start recording after temporary breakpoint is hit ",
            "   --stop_at <breakpoint_location_stop]    : stop recording after temporary breakpoint is hit ",
            "   --log <filename.log>                    : store output instead of printing it on stdout",
            "   --command <gdb_command>                 : execute gdb command, e.g. 'print $rax', multiple --command arguments can be given",
            "",
        ]
        print("\n".join(output))
            

    def invoke(self, arg, from_tty):
        args = gdb.string_to_argv(arg)
        thread_id = None
        log_file = None
        custom_commands = []
        bp_start_at = None
        bp_stop_at = None

        # Parse optional arguments
        while args and args[0].startswith('--'):
            if args[0] == '--thread' and len(args) >= 2:
                thread_id = args[1]
                args = args[2:]
            elif args[0] == '--log' and len(args) >= 2:
                log_file = args[1]
                args = args[2:]
            elif args[0] == '--command' and len(args) >= 2:
                custom_commands.append(args[1])
                args = args[2:]
            elif args[0] == '--help' :
                self.print_help()
                return

            else:
                self.print_help()
                print(f"Unknown option {args[0]}")
                return

        # Validate remaining arguments
        if len(args) < 2:
            self.print_help()
            return

        bp_location = args[0]
        targets = args[1:]

        # Set the breakpoint
        try:
            breakpoint_cmd = f"break {bp_location}"
            if thread_id:
                breakpoint_cmd += f" thread {thread_id}"
            rets = gdb.execute(breakpoint_cmd, to_string=True)
            if "not defined" in rets:
                print(f"[x] Can't find breakpoint at: '{bp_location}'")
                return
        except gdb.error as e:
            print(f"Failed to set breakpoint: {e}")
            return

        # Get the breakpoint number just created (last one)
        bp = gdb.breakpoints()[-1]
        bp_id = bp.number


        # Build command block
        command_lines = [
            f"commands {bp_id}",
            "silent",
            "python",
            "import gdb",
            "values = ''",
            "command_output = ''",
            f"targets = {repr(targets)}",
            f"custom_commands = {repr(custom_commands)}"
        ]

        command_lines += [
            "for target in targets:",
            "   try:",
            "       if target.startswith('0x'):",
            "           addr = int(target, 16)",
            "           val = gdb.inferiors()[0].read_memory(addr, 8)",
            "           value = target + ' = ' + hex(int.from_bytes(val, byteorder='little'))",
            "       else:",
            "           val = gdb.parse_and_eval(target)",
            "           value = str(val)",
            #"           if val.address:",
            #"               value = int(val.address)",
            #"           else:",
            #"               value = int(val)",
            "       values += value + '\\n'",
            "   except Exception as e:",
            "       values += f'Cannot read {target} <error: {e}>\\n'"
        ]

        # Run the extra command if provided
        command_lines += [
            "if custom_commands :",
            "    for custom_command in custom_commands:",
            "        try:",
            "            command_output += gdb.execute(f'{custom_command}', to_string=True) + \"\\n\"",
            "        except Exception as e:",
            "            command_output += f'<error running command {custom_command}: {e}>' + \"\\n\""
        ]

        # Output handling
        if log_file:
            with open(log_file, "w") as fp:
                fp.write("")
                fp.close()
            command_lines += [
                f"with open({repr(log_file)}, 'a') as f:",
                "    f.write(values)",
                "    if command_output:",
                "        f.write(f' {command_output}')",
                "    f.write('\\n')",
            ]
        else:
            command_lines += [
                "print(values)",
                "if command_output:",
                "    print(command_output)"
            ]

        # End command
        command_lines += [
            "end",  # end python
            "continue",
            "end"
        ]

        gdb.execute("\n".join(command_lines))




#################################
#################################
## Search object size 

# generated with gpt
import subprocess
import shutil
import re
from collections import defaultdict
from typing import Dict, List

# ---------------------------
# Check if ag is installed
# ---------------------------
def is_ag_installed() -> bool:
    """Check if 'ag' (The Silver Searcher) is installed."""
    return shutil.which("ag") is not None


# ---------------------------
# Run ag and collect matches
# ---------------------------
def run_ag(search_str: str, extensions: List[str], search_path: str) -> Dict[str, List[str]]:
    """
    Run ag for the given search string in search_path and return matches grouped by filename.
    Only includes files with given extensions.
    """
    if not is_ag_installed():
        raise RuntimeError("'ag' is not installed on this system.")

    # Build extension filter for ag
    ext_args = []
    if extensions:
        ext_args = ["-G", f"\\.({'|'.join(extensions)})$"]

    # Run ag
    cmd = ["ag", "--nogroup", "--nocolor", search_str, search_path] + ext_args
    #cmd = ["ag", "--nogroup", "--nocolor", search_str, search_path] + ["-G", ".c$"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    matches_per_file = defaultdict(list)
    for line in result.stdout.splitlines():
        # ag --nogroup output format: filename:line_number:content
        parts = line.split(":", 2)
        if len(parts) == 3:
            filename, _, content = parts
            matches_per_file[filename].append(content.strip())

    return matches_per_file

# ---------------------------
# Apply regex extraction
# ---------------------------
def extract_with_regex(matches_per_file: Dict[str, List[str]], pattern: str, regex_index: int) -> Dict[str, List[str]]:
    """
    Apply regex extraction to each matched line, storing results per file.
    """
    extracted_per_file = defaultdict(list)
    for filename, lines in matches_per_file.items():
        for line in lines:
            match = re.match(pattern, line)
            if match:
                extracted_per_file[filename].append(match.group(regex_index))
    return extracted_per_file



class pa_Search_Object_Size(gdb.Command):
    """
        Search objects occupying the size argument given. (It might be imprecise)

        partially generated by gpt
    """

    cache_ = {
        "file_path_per_object" : {},
        "object_per_file_path" : {},
        "ptype_objects" : {},
        "ptype_objects_str" : {},
        "wrong_ptype_objects" : {},
        "sizeof_objects" : {},
        "ptype_command_cache" : {},
    }

    cache_v8_ = {
        "file_path_per_object" : {},
        "object_per_file_path" : {},
        "ptype_objects" : {},
        "ptype_objects_str" : {},
        "wrong_ptype_objects" : {},
        "sizeof_objects" : {},
        "ptype_command_cache" : {},
    }




    def __init__(self):
        super().__init__("pa_search_object_size", gdb.COMMAND_USER)

    def print_usage(self):
        print(
            """Usage: pa_search_object_size [options] <size>

            Search objects occupying the size argument given. (It might be imprecise)
            output is cached in order to save-up some times

            Options
                --help : print this message
                --clean : clean search cache
                --blink : flag telling to search on blink fastmalloc (default True if no --v8 flag is given)
                --v8    : flag telling to search on v8 'Malloced' classes (default False)


            TODO:
                - add Managed<IftNativeAllocations>::Allocate calls -v8
                - add ToCString (non-controllable) -v8
                - GetStringOption (//) -v8
 
            """
        )

    def int(self, target, conv=10):
        addr = None
        target = target.strip().lower()
        try:
            if target.startswith('0x') or target.startswith('-0x'):
                addr = int(target, conv)
            else:
                addr = int(gdb.parse_and_eval(target))
        except Exception as ex:
            print(f"[x] Can't parse integer/symbol '{target}' exception: {ex}")
        return addr

    def invoke(self, arg, from_tty):
        args = gdb.string_to_argv(arg)
        print_help = False
        do_clean = False
        search_on_blink = False
        search_on_v8 = False
        self.ALLOC_ALIGN = 0x10

        while args and args[0].startswith('--'):
            if args[0] == '--help' :
                print_help = True
                break
            elif args[0] == "--clean" :
                do_clean = True
                args = args[1:]
            elif args[0] == "--blink" :
                search_on_blink = True
                args = args[1:]
            elif args[0] == "--v8" :
                search_on_v8 = True
                args = args[1:]

            else:
                print(f"Unknown option {args[0]}")
                print_help = True
                break

        size = None
        if len(args) > 0:
            size = self.int(args[0], 16)

        if size == None:
            print_help = True

        if size % self.ALLOC_ALIGN :
            print(f"[x] Size is not {hex(self.ALLOC_ALIGN)} aligned")
            print_help = True

        if not (search_on_v8 or search_on_blink):
            search_on_blink = True

        if print_help:
            self.print_usage()
            return

        if not is_ag_installed():
            print("Error: 'ag' (The Silver Searcher) is not installed.")
            return

        if search_on_blink:
            print("Blink search result:")
            self.search_on_blink(
                size,
                "CSSVariableData",                                  # this should be a string that will return an object with that path, if you exec "list <var>" returns path
                "../../third_party/blink/renderer",                 # if the path matches we are on the right track
                "USING_FAST_MALLOC",                                # then from that folder run the-silver-searcher command and match this string
                allowed_ext_ = ["c", "cc", "h", "cpp", "hpp"],      # accepted extension
                regex_ = r"USING_FAST_MALLOC\((\w+)",               # extract class name
                regex_index_ = 1,
                namespace_ = "blink::",                             # on each class name append the following namespace
                do_clean = do_clean                                 # true/false ignore cached results
            )

        if search_on_v8:
            print("V8 search result:")
            self.search_on_blink(
                size,
                "ArrayBufferExtension",
                "../../v8/src",
                ": public Malloced",
                allowed_ext_ = ["c", "cc", "h", "cpp", "hpp"],
                regex_ = r"^class( V8_EXPORT_PRIVATE)* (\w+)( final)* : public Malloced ",
                regex_index_ = 2,
                namespace_ = "v8::internal::",
                do_clean = do_clean
            )




    def search_on_blink(self, size, find_, path_, grep_on_, allowed_ext_=[], regex_=r"", regex_index_=0, namespace_="", is_blink=True, do_clean=False):
        ## Get a symbol object (example: function "main")
        #cmd_ = f"list {find_}"
        #rets = gdb.execute(cmd_, to_string=True)
        #file_list = rets.split("file: ")
        str_ = []
        SEARCH_PATH = path_
        SEARCH_STRING = grep_on_
        ALLOWED_EXTENSIONS = allowed_ext_
        CUSTOM_REGEX = regex_
        
        cache_ = pa_Search_Object_Size.cache_
        if not is_blink :
            cache_ = pa_Search_Object_Size.cache_v8_

        if do_clean or cache_["file_path_per_object"] == {}:
            print("First time running the command or '--clean' argument was given  (it can take a while..)")
            print(f"[*] Running ag search in {SEARCH_PATH}...")
            matches = run_ag(SEARCH_STRING, ALLOWED_EXTENSIONS, SEARCH_PATH)
            print(f"Found matches in {len(matches)} files.")

            matches_result = extract_with_regex(matches, CUSTOM_REGEX, regex_index_)
            wrong_ptype_objects = []
            file_path_per_object = {}
            object_per_file_path = {}
            ptype_objects = []
            ptype_objects_str = []
            sizeof_objects = {}
            ptype_command_cache = {}

            for file, items in matches_result.items():
                for item in items:
                    item = f"{namespace_}{item}"
                    print(item)
                    try:
                        obj_ = gdb.lookup_type(item)
                        sizeof = obj_.sizeof
                        if file not in file_path_per_object:
                            file_path_per_object[file] = []

                        ptype_objects.append(obj_)
                        ptype_objects_str.append(item)
                        idx_ = len(ptype_objects)-1
                        file_path_per_object[file].append(idx_)
                        object_per_file_path[idx_] = file


                        sizeof_align = sizeof
                        if sizeof % self.ALLOC_ALIGN:
                            sizeof_align += (self.ALLOC_ALIGN - sizeof % self.ALLOC_ALIGN)

                        if sizeof_align not in sizeof_objects:
                            sizeof_objects[sizeof_align] = []
                        
                        sizeof_objects[sizeof_align].append(idx_)

                    except gdb.error as ex:
                        wrong_ptype_objects.append(f"{item} at {file}")
                    print(item)

            for k in cache_:
                cache_[k] = locals()[k]

        #for k in cache_:
        #    locals()[k] = cache_[k]
        #print(locals()["sizeof_objects"])  # don't know why it does not work
        object_per_file_path = cache_["object_per_file_path"]
        ptype_objects = cache_["ptype_objects"]
        ptype_objects_str = cache_["ptype_objects_str"]
        sizeof_objects = cache_["sizeof_objects"]
        ptype_command_cache = cache_["ptype_command_cache"]

        obj_matches = []
        for x in range(0x10, size+1, 0x10):
            obj_matches.extend(sizeof_objects[x])

        str_.append("Candidates:")
        for x in obj_matches:
            file_path = object_per_file_path[x]
            obj_ = ptype_objects[x]
            obj_str_ = ptype_objects_str[x]
            str_.append(f"{obj_str_} [size:{hex(obj_.sizeof)}] '{file_path}'")

            if x not in ptype_command_cache:
                try:
                    cmd_ = f"ptype {obj_str_}"
                    ptype_command_cache[x] = gdb.execute(cmd_, to_string=True)
                except gdb.error as ex:
                    ptype_command_cache[x] = f"[x] error: {ex}"

            ptype_cmd_output = ptype_command_cache[x]
            str_.append(ptype_cmd_output + "\n")

        print("\n".join(str_))




pa_Collect_address()





pa_SetPartitionRoot()
pa_PrintMetadataPage()
pa_Search()
pa_Search_Object_Size()



