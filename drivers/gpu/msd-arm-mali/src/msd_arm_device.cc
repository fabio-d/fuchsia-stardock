// Copyright 2017 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "msd_arm_device.h"
#include "magma_util/dlog.h"
#include "magma_util/macros.h"
#include <bitset>
#include <cstdio>
#include <ddk/debug.h>
#include <string>

#include "registers.h"

// This is the index into the mmio section of the mdi.
enum MmioIndex {
    kMmioIndexRegisters = 0,
};

enum InterruptIndex {
    kInterruptIndexJob = 0,
    kInterruptIndexMmu = 1,
    kInterruptIndexGpu = 2,
};

//////////////////////////////////////////////////////////////////////////////////////////////////

std::unique_ptr<MsdArmDevice> MsdArmDevice::Create(void* device_handle, bool start_device_thread)
{
    auto device = std::make_unique<MsdArmDevice>();

    if (!device->Init(device_handle))
        return DRETP(nullptr, "Failed to initialize MsdArmDevice");

    if (start_device_thread)
        device->StartDeviceThread();

    return device;
}

MsdArmDevice::MsdArmDevice() { magic_ = kMagic; }

MsdArmDevice::~MsdArmDevice() { Destroy(); }

void MsdArmDevice::Destroy()
{
    DLOG("Destroy");
    CHECK_THREAD_NOT_CURRENT(device_thread_id_);

    DisableInterrupts();

    interrupt_thread_quit_flag_ = true;

    if (gpu_interrupt_)
        gpu_interrupt_->Signal();
    if (job_interrupt_)
        job_interrupt_->Signal();
    if (mmu_interrupt_)
        mmu_interrupt_->Signal();

    if (gpu_interrupt_thread_.joinable()) {
        DLOG("joining GPU interrupt thread");
        gpu_interrupt_thread_.join();
        DLOG("joined");
    }
    if (job_interrupt_thread_.joinable()) {
        DLOG("joining Job interrupt thread");
        job_interrupt_thread_.join();
        DLOG("joined");
    }
    if (mmu_interrupt_thread_.joinable()) {
        DLOG("joining MMU interrupt thread");
        mmu_interrupt_thread_.join();
        DLOG("joined");
    }
    device_thread_quit_flag_ = true;

    if (device_request_semaphore_)
        device_request_semaphore_->Signal();

    if (device_thread_.joinable()) {
        DLOG("joining device thread");
        device_thread_.join();
        DLOG("joined");
    }
}

bool MsdArmDevice::Init(void* device_handle)
{
    DLOG("Init");
    platform_device_ = magma::PlatformDevice::Create(device_handle);
    if (!platform_device_)
        return DRETF(false, "Failed to initialize device");

    std::unique_ptr<magma::PlatformMmio> mmio = platform_device_->CpuMapMmio(
        kMmioIndexRegisters, magma::PlatformMmio::CACHE_POLICY_UNCACHED_DEVICE);
    if (!mmio)
        return DRETF(false, "failed to map registers");

    register_io_ = std::make_unique<RegisterIo>(std::move(mmio));

    device_request_semaphore_ = magma::PlatformSemaphore::Create();

    if (!InitializeInterrupts())
        return false;

    EnableInterrupts();

    return true;
}

std::unique_ptr<MsdArmConnection> MsdArmDevice::Open(msd_client_id_t client_id)
{
    return MsdArmConnection::Create(client_id);
}

int MsdArmDevice::DeviceThreadLoop()
{
    magma::PlatformThreadHelper::SetCurrentThreadName("DeviceThread");

    device_thread_id_ = std::make_unique<magma::PlatformThreadId>();
    CHECK_THREAD_IS_CURRENT(device_thread_id_);

    DLOG("DeviceThreadLoop starting thread 0x%lx", device_thread_id_->id());

    std::unique_lock<std::mutex> lock(device_request_mutex_, std::defer_lock);

    while (true) {
        device_request_semaphore_->Wait();

        if (device_thread_quit_flag_)
            break;
    }

    DLOG("DeviceThreadLoop exit");
    return 0;
}

int MsdArmDevice::GpuInterruptThreadLoop()
{
    magma::PlatformThreadHelper::SetCurrentThreadName("Gpu InterruptThread");
    DLOG("GPU Interrupt thread started");

    while (!interrupt_thread_quit_flag_) {
        DLOG("GPU waiting for interrupt");
        gpu_interrupt_->Wait();
        DLOG("GPU Returned from interrupt wait!");

        if (interrupt_thread_quit_flag_)
            break;

        auto irq_status = registers::GpuIrqFlags::GetStatus().ReadFrom(register_io_.get());
        auto clear_flags = registers::GpuIrqFlags::GetIrqClear().FromValue(irq_status.reg_value());
        clear_flags.WriteTo(register_io_.get());

        dprintf(ERROR, "Got unexpected GPU IRQ %d\n", irq_status.reg_value());
        gpu_interrupt_->Complete();
    }

    DLOG("GPU Interrupt thread exited");
    return 0;
}

int MsdArmDevice::JobInterruptThreadLoop()
{
    magma::PlatformThreadHelper::SetCurrentThreadName("Job InterruptThread");
    DLOG("Job Interrupt thread started");

    while (!interrupt_thread_quit_flag_) {
        DLOG("Job waiting for interrupt");
        job_interrupt_->Wait();
        DLOG("Job Returned from interrupt wait!");

        if (interrupt_thread_quit_flag_)
            break;

        auto irq_status = registers::JobIrqFlags::GetStatus().ReadFrom(register_io_.get());
        auto clear_flags = registers::JobIrqFlags::GetIrqClear().FromValue(irq_status.reg_value());
        clear_flags.WriteTo(register_io_.get());

        dprintf(ERROR, "Got unexpected Job IRQ %d\n", irq_status.reg_value());
        job_interrupt_->Complete();
    }

    DLOG("Job Interrupt thread exited");
    return 0;
}

int MsdArmDevice::MmuInterruptThreadLoop()
{
    magma::PlatformThreadHelper::SetCurrentThreadName("MMU InterruptThread");
    DLOG("MMU Interrupt thread started");

    while (!interrupt_thread_quit_flag_) {
        DLOG("MMU waiting for interrupt");
        job_interrupt_->Wait();
        DLOG("MMU Returned from interrupt wait!");

        if (interrupt_thread_quit_flag_)
            break;

        auto irq_status = registers::MmuIrqFlags::GetStatus().ReadFrom(register_io_.get());
        auto clear_flags = registers::MmuIrqFlags::GetIrqClear().FromValue(irq_status.reg_value());
        clear_flags.WriteTo(register_io_.get());

        dprintf(ERROR, "Got unexpected MMU IRQ %d\n", irq_status.reg_value());

        mmu_interrupt_->Complete();
    }

    DLOG("MMU Interrupt thread exited");
    return 0;
}

void MsdArmDevice::StartDeviceThread()
{
    DASSERT(!device_thread_.joinable());
    device_thread_ = std::thread([this] { this->DeviceThreadLoop(); });

    gpu_interrupt_thread_ = std::thread([this] { this->GpuInterruptThreadLoop(); });
    job_interrupt_thread_ = std::thread([this] { this->JobInterruptThreadLoop(); });
    mmu_interrupt_thread_ = std::thread([this] { this->MmuInterruptThreadLoop(); });
}

bool MsdArmDevice::InitializeInterrupts()
{
    // When it's initialize the reset completed flag may be set. Clear it so
    // we don't get a useless interrupt.
    auto clear_flags = registers::GpuIrqFlags::GetIrqClear().FromValue(0xffffffff);
    clear_flags.WriteTo(register_io_.get());

    gpu_interrupt_ = platform_device_->RegisterInterrupt(kInterruptIndexGpu);
    if (!gpu_interrupt_)
        return DRETF(false, "failed to register GPU interrupt");

    job_interrupt_ = platform_device_->RegisterInterrupt(kInterruptIndexJob);
    if (!job_interrupt_)
        return DRETF(false, "failed to register JOB interrupt");

    mmu_interrupt_ = platform_device_->RegisterInterrupt(kInterruptIndexMmu);
    if (!mmu_interrupt_)
        return DRETF(false, "failed to register MMU interrupt");

    return true;
}

void MsdArmDevice::EnableInterrupts()
{
    auto gpu_flags = registers::GpuIrqFlags::GetIrqMask().FromValue(0xffffffff);
    gpu_flags.WriteTo(register_io_.get());

    auto mmu_flags = registers::MmuIrqFlags::GetIrqMask().FromValue(0xffffffff);
    mmu_flags.WriteTo(register_io_.get());

    auto job_flags = registers::JobIrqFlags::GetIrqMask().FromValue(0xffffffff);
    job_flags.WriteTo(register_io_.get());
}

void MsdArmDevice::DisableInterrupts()
{
    auto gpu_flags = registers::GpuIrqFlags::GetIrqMask().FromValue(0);
    gpu_flags.WriteTo(register_io_.get());

    auto mmu_flags = registers::MmuIrqFlags::GetIrqMask().FromValue(0);
    mmu_flags.WriteTo(register_io_.get());

    auto job_flags = registers::JobIrqFlags::GetIrqMask().FromValue(0);
    job_flags.WriteTo(register_io_.get());
}

//////////////////////////////////////////////////////////////////////////////////////////////////

msd_connection_t* msd_device_open(msd_device_t* dev, msd_client_id_t client_id)
{
    auto connection = MsdArmDevice::cast(dev)->Open(client_id);
    if (!connection)
        return DRETP(nullptr, "MsdArmDevice::Open failed");
    return new MsdArmAbiConnection(std::move(connection));
}

void msd_device_destroy(msd_device_t* dev) { delete MsdArmDevice::cast(dev); }

uint32_t msd_device_get_id(msd_device_t* dev) { return 0; }

magma_status_t msd_device_query(msd_device_t* device, uint64_t id, uint64_t* value_out)
{
    return DRET_MSG(MAGMA_STATUS_INVALID_ARGS, "unhandled id %" PRIu64, id);
}

void msd_device_dump_status(msd_device_t* device) {}

magma_status_t msd_device_display_get_size(msd_device_t* dev, magma_display_size* size_out)
{
    return MAGMA_STATUS_OK;
}
