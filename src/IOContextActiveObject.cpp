#include <deque>
#include <thread>
#include <boost/bind/bind.hpp>

#include <gears/IOContextActiveObject.hpp>

namespace Gears
{
  struct IOContextActiveObject::Impl
  {
    boost::asio::io_context io_context;
    std::deque<std::thread> thread_pool;
    std::unique_ptr<boost::asio::io_context::work> io_context_work;
  };

  IOContextActiveObject::IOContextActiveObject(int threads_count):
    threads_count_(threads_count),
    impl_(std::make_unique<Impl>())
  {
  }

  IOContextActiveObject::~IOContextActiveObject() noexcept
  {
  }

  boost::asio::io_context& IOContextActiveObject::io_context()
  {
    return impl_->io_context;
  }

  void IOContextActiveObject::activate_object_()
  {
    // Make sure that io_context run() will not return.
    impl_->io_context_work.reset(new boost::asio::io_context::work(impl_->io_context));

    // Start running of tasks.
    for(int thread_i = 0; thread_i < threads_count_; ++thread_i)
    {
      impl_->thread_pool.emplace_back(std::thread(
        boost::bind(&boost::asio::io_context::run, &impl_->io_context)));
    }
  }

  void IOContextActiveObject::deactivate_object_()
  {
    impl_->io_context.stop();
  }

  void IOContextActiveObject::wait_object_()
  {
    for (auto& thread : impl_->thread_pool)
    {
      thread.join();
    }

    impl_->thread_pool.clear();
  }

  void IOContextActiveObject::clear()
  {
    Gears::Condition::Guard lock(cond_);
    impl_->io_context_work.reset();
  }
}
