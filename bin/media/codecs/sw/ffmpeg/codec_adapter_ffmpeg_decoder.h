// Copyright 2018 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef GARNET_BIN_MEDIA_CODECS_SW_FFMPEG_CODEC_ADAPTER_FFMPEG_DECODER_H_
#define GARNET_BIN_MEDIA_CODECS_SW_FFMPEG_CODEC_ADAPTER_FFMPEG_DECODER_H_

#include <threads.h>
#include <optional>
#include <queue>

#include <lib/async-loop/cpp/loop.h>
#include <lib/fxl/synchronization/thread_annotations.h>
#include <lib/media/codec_impl/codec_adapter.h>
#include <lib/media/codec_impl/codec_input_item.h>

#include "avcodec_context.h"

class CodecAdapterFfmpegDecoder : public CodecAdapter {
 public:
  CodecAdapterFfmpegDecoder(std::mutex& lock,
                            CodecAdapterEvents* codec_adapter_events);
  ~CodecAdapterFfmpegDecoder();

  bool IsCoreCodecRequiringOutputConfigForFormatDetection() override;
  void CoreCodecInit(const fuchsia::mediacodec::CodecFormatDetails&
                         initial_input_format_details) override;
  void CoreCodecStartStream() override;
  void CoreCodecQueueInputFormatDetails(
      const fuchsia::mediacodec::CodecFormatDetails&
          per_stream_override_format_details) override;
  void CoreCodecQueueInputPacket(CodecPacket* packet) override;
  void CoreCodecQueueInputEndOfStream() override;
  void CoreCodecStopStream() override;
  void CoreCodecAddBuffer(CodecPort port, const CodecBuffer* buffer) override;
  void CoreCodecConfigureBuffers(
      CodecPort port,
      const std::vector<std::unique_ptr<CodecPacket>>& packets) override;
  void CoreCodecRecycleOutputPacket(CodecPacket* packet) override;
  void CoreCodecEnsureBuffersNotConfigured(CodecPort port) override;
  std::unique_ptr<const fuchsia::mediacodec::CodecOutputConfig>
  CoreCodecBuildNewOutputConfig(
      uint64_t stream_lifetime_ordinal,
      uint64_t new_output_buffer_constraints_version_ordinal,
      uint64_t new_output_format_details_version_ordinal,
      bool buffer_constraints_action_required) override;
  void CoreCodecMidStreamOutputBufferReConfigPrepare() override;
  void CoreCodecMidStreamOutputBufferReConfigFinish() override;

 private:
  struct BufferAllocation {
    const CodecBuffer* buffer;
    size_t bytes_used;
  };

  // SyncQueue is safe for use where any number of threads push elements and one
  // thread takes the elements.
  //
  // Methods should not be called while holding lock.
  //
  // By default WaitForElement will block until StopAllWaits is called. To
  // block again, call Reset.
  template <typename T>
  class SyncQueue {
   public:
    // Extracts the values from the SyncQueue and destroys the SyncQueue.
    static std::queue<T> Extract(SyncQueue&& source) {
      std::lock_guard<std::mutex> lock(source.lock_);
      return std::move(source.queue_);
    }

    explicit SyncQueue(std::mutex& lock) : lock_(lock), should_wait_(true) {}

    // Returns true iff the queue is empty.
    bool Empty() {
      std::lock_guard<std::mutex> lock(lock_);
      return queue_.empty();
    }

    // Adds a new element to the queue and notifies any threads waiting on a
    // new element.
    void Push(T element) {
      {
        std::lock_guard<std::mutex> lock(lock_);
        queue_.push(std::move(element));
      }
      should_wait_condition_.notify_all();
    }

    // Get an element or block until one is available if the queue is empty.
    // If a thread calls StopAllWaits(), std::nullopt is returned.
    std::optional<T> WaitForElement() {
      std::unique_lock<std::mutex> lock(lock_);
      should_wait_condition_.wait(
          lock, [this] { return !queue_.empty() || !should_wait_; });

      if (!should_wait_) {
        return std::nullopt;
      }

      T element = std::move(queue_.front());
      queue_.pop();
      return element;
    }

    // Stops all waiting threads. We call this when a stream is stopped to abort
    // the input processing loop.
    void StopAllWaits() {
      {
        std::lock_guard<std::mutex> lock(lock_);
        should_wait_ = false;
      }
      should_wait_condition_.notify_all();
    }

    // Resets the queue to its default state.
    void Reset(bool keep_data = false) {
      std::lock_guard<std::mutex> lock(lock_);
      should_wait_ = true;
      if (!keep_data) {
        queue_ = std::queue<T>();
      }
    }

   private:
    std::condition_variable should_wait_condition_;
    std::mutex& lock_;
    std::queue<T> queue_ FXL_GUARDED_BY(lock_);
    bool should_wait_ FXL_GUARDED_BY(lock_);

    DISALLOW_COPY_AND_ASSIGN_ALLOW_MOVE(SyncQueue);
  };

  // Reads the opaque pointer from our free callback and routes it to our
  // instance. The opaque pointer is provided when we set up a free callback
  // when providing buffers to the decoder in GetBuffer.
  static void BufferFreeCallbackRouter(void* opaque, uint8_t* data);

  // A callback handler for when buffers are freed by the decoder, which returns
  // them to our pool. The opaque pointer is provided when we set up a free
  // callback when providing buffers to the decoder in GetBuffer.
  void BufferFreeHandler(uint8_t* data);

  // Processes input in a loop. Should only execute on input_processing_thread_.
  // Loops for the lifetime of a stream.
  void ProcessInputLoop();

  // Allocates buffer for a frame for ffmpeg.
  int GetBuffer(const AvCodecContext::DecodedOutputInfo& decoded_output_info,
                AVCodecContext* avcodec_context, AVFrame* frame, int flags);

  // Decodes frames until the decoder is empty.
  void DecodeFrames();

  void WaitForInputProcessingLoopToEnd();

  SyncQueue<CodecInputItem> input_queue_;
  SyncQueue<const CodecBuffer*> free_output_buffers_;
  SyncQueue<CodecPacket*> free_output_packets_;
  std::optional<AvCodecContext::DecodedOutputInfo> decoded_output_info_
      FXL_GUARDED_BY(lock_);

  // When no references exist to our buffers in the decoder's refcounting
  // anymore, the decoder will execute our BufferFreeHandler that looks up our
  // buffer here and adds it to our free list.
  //
  // We also look here when frames come out of the decoder, to associate an
  // output packet with the the buffer.
  std::map<uint8_t*, BufferAllocation> in_use_by_decoder_ FXL_GUARDED_BY(lock_);
  // This keeps buffers alive via the decoder's refcount until the client is
  // done with them.
  std::map<CodecPacket*, AvCodecContext::AVFramePtr> in_use_by_client_
      FXL_GUARDED_BY(lock_);

  uint64_t input_format_details_version_ordinal_;

  async::Loop input_processing_loop_;
  thrd_t input_processing_thread_;
  std::unique_ptr<AvCodecContext> avcodec_context_;
};

#endif  // GARNET_BIN_MEDIA_CODECS_SW_FFMPEG_CODEC_ADAPTER_FFMPEG_DECODER_H_