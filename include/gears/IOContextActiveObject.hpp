#pragma once

#include <boost/asio/io_context.hpp>
#include <gears/ActiveObject.hpp>

namespace diam2json
{
  class IOContextActiveObject: public Gears::SimpleActiveObject
  {
  public:
    IOContextActiveObject(int threadsNumber);

    virtual ~IOContextActiveObject() noexcept;

    void clear();

    boost::asio::io_context& io_context();

  protected:
    void activate_object_() override;

    void deactivate_object_() override;

    void wait_object_() override;

  private:
    struct Impl;

  private:
    const int threads_count_;
    std::unique_ptr<Impl> impl_;
  };
}
