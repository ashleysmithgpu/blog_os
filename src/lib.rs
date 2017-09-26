// Copyright 2016 Philipp Oppermann. See the README.md
// file at the top-level directory of this distribution.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![feature(lang_items)]
#![feature(const_fn, unique)]
#![feature(alloc)]
#![feature(asm)]
#![feature(naked_functions)]
#![feature(abi_x86_interrupt)]
#![no_std]

extern crate rlibc;
extern crate volatile;
extern crate spin;
extern crate multiboot2;
#[macro_use]
extern crate bitflags;
extern crate x86_64;
#[macro_use]
extern crate once;
extern crate bit_field;
#[macro_use]
extern crate lazy_static;

extern crate hole_list_allocator as allocator;
#[macro_use]
extern crate alloc;

#[macro_use]
mod vga_buffer;
mod memory;

mod interrupts;



// Sys calls
/*fn sys_call() {

	println!("sys_call!");
}*/



#[no_mangle]
pub extern "C" fn rust_main(multiboot_information_address: usize) {

	for x in 0..500 {

		println!("Hello World{}", x);
	}


    // ATTENTION: we have a very small stack and no guard page
    vga_buffer::clear_screen();
    println!("Hello World{}", "!");

    let boot_info = unsafe { multiboot2::load(multiboot_information_address) };
    enable_nxe_bit();
    enable_write_protect_bit();

    // set up guard page and map the heap pages
    let mut memory_controller = memory::init(boot_info);

    // initialize our IDT
    interrupts::init(&mut memory_controller);

	use alloc::vec::Vec;
	let usermodecode: Vec<u8> = vec![
0x90,
0x90,
0x90,
0x90,
0x90,
0x90,
0x90,
0x90,
0x90,
0x90,
0x90,
0x90,
0x90,
0x90,
0xb0,
0x37,
0xc7,
0x04,
0x25,
0x00,
0x80,
0x0b,
0x00,
0x45,
0x4f,
0x52,
0x4f,
0xc7,
0x04,
0x25,
0x04,
0x80,
0x0b,
0x00,
0x52,
0x4f,
0x3a,
0x4f,
0xc7,
0x04,
0x25,
0x08,
0x80,
0x0b,
0x00,
0x20,
0x4f,
0x20,
0x4f,
0x88,
0x04,
0x25,
0x0a,
0x80,
0x0b,
0x00,
0xf4];

	println!("Enabling syscalls");

	enable_syscalls_bit();

    println!("Doing sysret");

	let x: i32 = usermodecode.as_ptr() as i32;

//	x |= 800000000000000;

	println!("x {:?}\n", x);

	unsafe {
	/*	asm!("mov $0, %rcx"
			:
			: "r"(usermodecode.as_ptr())
			:
			:
			);*/

		asm!(r"movq $$1073741824, %rcx");
		/*:
		: "r"(x)
		: "rcx"
		:);*/
		asm!(r"sysretq" ::::); // TODO: why does this asm instruction seem backwards? 0x48070f48 should be 0x480f0748
	}

	/*
    fn stack_overflow() {
        stack_overflow(); // for each recursion, the return address is pushed
    }

    // trigger a stack overflow
    stack_overflow();*/

    println!("It did not crash!");
    loop {}
}

/*fn setup_sys_calls() {
    use x86_64::registers::msr::{IA32_STAR, IA32_LSTAR, wrmsr};

    unsafe {
        wrmsr(IA32_LSTAR, sys_call as u64);
    }
}*/

fn enable_syscalls_bit() {
    use x86_64::registers::msr::{IA32_EFER, rdmsr, wrmsr};

    let syscall_bit = 1;
    unsafe {
        let efer = rdmsr(IA32_EFER);
        wrmsr(IA32_EFER, efer | syscall_bit);
    }
}

fn enable_nxe_bit() {
    use x86_64::registers::msr::{IA32_EFER, rdmsr, wrmsr};

    let nxe_bit = 1 << 11;
    unsafe {
        let efer = rdmsr(IA32_EFER);
        wrmsr(IA32_EFER, efer | nxe_bit);
    }
}

fn enable_write_protect_bit() {
    use x86_64::registers::control_regs::{cr0, cr0_write, Cr0};

    unsafe { cr0_write(cr0() | Cr0::WRITE_PROTECT) };
}

#[cfg(not(test))]
#[lang = "eh_personality"]
extern "C" fn eh_personality() {}

#[cfg(not(test))]
#[lang = "panic_fmt"]
#[no_mangle]
pub extern "C" fn panic_fmt(fmt: core::fmt::Arguments, file: &'static str, line: u32) -> ! {
    println!("\n\nPANIC in {} at line {}:", file, line);
    println!("    {}", fmt);
    loop {}
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn _Unwind_Resume() -> ! {
    loop {}
}
