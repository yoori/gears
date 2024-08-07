#ifndef GEARS_ISAAC_HPP_
#define GEARS_ISAAC_HPP_

#include <algorithm>
#include <cstdint>

#include <unistd.h>
#include <fcntl.h>

#include "Uncopyable.hpp"

namespace Gears
{
  /**
   * ISAAC cryptographically secure pseudo random number generator
   * with an average period of 2^8295
   * Not thread safe
   */
  class ISAAC: private Uncopyable
  {
  public:
    /**
     * Up limit for random numbers range.
     * This generator range is [0, RAND_MAXIMUM]
     */
    static const uint32_t RAND_MAXIMUM = ~static_cast<uint32_t>(0);

    /**
     * Constructor
     * Uses /dev/urandom for initialization
     */
    ISAAC() noexcept;

    /**
     * Constructor
     * @param value initial seed number
     */
    explicit
    ISAAC(const uint32_t value) noexcept;

    /**
     * Constructor
     * @param value pointer to data for initial seed (256 elements)
     */
    explicit
    ISAAC(const uint32_t* value) noexcept;

    /**
     * Initializes object
     * Uses /dev/urandom for initialization
     */
    void
    seed() noexcept;

    /**
     * Initializes object
     * @param value initial seed number
     */
    void
    seed(uint32_t value) noexcept;

    /**
     * Initializes object
     * @param value pointer to data for initial seed (256 elements)
     */
    void
    seed(const uint32_t* value) noexcept;

    /**
     * Creates next random number in the sequence
     * @return random number in [0..2^32-1] range
     */
    uint32_t
    rand() noexcept;

  protected:
    /**
     * Initializes state
     * @param value initial seed number
     * @param use_rand use random_ data or not
     */
    void
    initialize_(uint32_t value, bool use_rand) noexcept;

    void
    reinit_() noexcept;

  private:
    static
    void
    rng_step_(uint32_t*& m, uint32_t*& m2, uint32_t*& r, uint32_t* mm,
      uint32_t& a, uint32_t& b, uint32_t mix) noexcept;

    static const size_t SIZE = 256;

    uint32_t state_[SIZE];
    uint32_t aa_, bb_, cc_;

    uint32_t random_[SIZE];

    int left_;
    const uint32_t* next_;
  };
}

namespace Gears
{
  inline
  ISAAC::ISAAC() noexcept
  {
    seed();
  }

  inline
  ISAAC::ISAAC(const uint32_t value) noexcept
  {
    seed(value);
  }

  inline
  ISAAC::ISAAC(const uint32_t* value) noexcept
  {
    seed(value);
  }

  inline
  uint32_t
  ISAAC::rand() noexcept
  {
    if (!left_)
    {
      reinit_();
    }
    left_--;

    return *next_++;
  }

  inline
  void
  ISAAC::rng_step_(uint32_t*& m, uint32_t*& m2, uint32_t*& r, uint32_t* mm,
    uint32_t& a, uint32_t& b, uint32_t mix) noexcept
  {
    uint32_t x, y;

    x = *m;
    a = (a ^ mix) + *(m2++);
    *m++ = y = mm[(x >> 2) & 0xFF] + a + b;
    *r++ = b = mm[(y >> 10) & 0xFF] + x;
  }

  inline
  void
  ISAAC::reinit_() noexcept
  {
    uint32_t a = aa_;
    uint32_t b = bb_ + ++cc_;
    uint32_t* mm = state_;
    uint32_t* m = mm;
    uint32_t* m2 = mm + SIZE / 2;
    uint32_t* mend = m2;
    uint32_t* r = random_;

    while (m < mend)
    {
      rng_step_(m, m2, r, mm, a, b, a << 13);
      rng_step_(m, m2, r, mm, a, b, a >> 6);
      rng_step_(m, m2, r, mm, a, b, a << 2);
      rng_step_(m, m2, r, mm, a, b, a >> 16);
    }
    m2 = mm;
    while (m2 < mend)
    {
      rng_step_(m, m2, r, mm, a, b, a << 13);
      rng_step_(m, m2, r, mm, a, b, a >> 6);
      rng_step_(m, m2, r, mm, a, b, a << 2);
      rng_step_(m, m2, r, mm, a, b, a >> 16);
    }

    aa_ = a;
    bb_ = b;

    left_ = SIZE;
    next_ = random_;
  }

  inline
  void
  ISAAC::seed() noexcept
  {
    int urandom = open("/dev/urandom", O_RDONLY);
    if (urandom >= 0)
    {
      uint32_t value[SIZE];
      bool success;
      for (;;)
      {
        ssize_t res = read(urandom, value, sizeof(value));
        success = res == sizeof(value);
        if (res <= 0 || success)
        {
          break;
        }
      }
      close(urandom);
      if (success)
      {
        seed(value);
        return;
      }
    }

    seed(static_cast<const uint32_t*>(0));
  }

  inline
  void
  ISAAC::seed(uint32_t value) noexcept
  {
    initialize_(value, false);
    reinit_();
  }

  inline
  void
  ISAAC::seed(const uint32_t* value) noexcept
  {
    if (value)
    {
      std::copy(value, value + SIZE, random_);
    }
    initialize_(0x9E3779B9u, true);
  }

  inline
  void
  ISAAC::initialize_(uint32_t value, bool use_rand) noexcept
  {
    class Mixer
    {
    public:
      Mixer(uint32_t value) noexcept
      {
        std::fill(data_, data_ + 8, value);
      }

      void
      mix() noexcept
      {
        data_[0] ^= data_[1] << 11;
        data_[3] += data_[0];
        data_[1] += data_[2];
        data_[1] ^= data_[2] >> 2;
        data_[4] += data_[1];
        data_[2] += data_[3];
        data_[2] ^= data_[3] << 8;
        data_[5] += data_[2];
        data_[3] += data_[4];
        data_[3] ^= data_[4] >> 16;
        data_[6] += data_[3];
        data_[4] += data_[5];
        data_[4] ^= data_[5] << 10;
        data_[7] += data_[4];
        data_[5] += data_[6];
        data_[5] ^= data_[6] >> 4;
        data_[0] += data_[5];
        data_[6] += data_[7];
        data_[6] ^= data_[7] << 8;
        data_[1] += data_[6];
        data_[7] += data_[0];
        data_[7] ^= data_[0] >> 9;
        data_[2] += data_[7];
        data_[0] += data_[1];
      }

      void
      add(const uint32_t* source) noexcept
      {
        for (int i = 0; i < 8; i++)
        {
          data_[i] += source[i];
        }
      }

      void
      copy_to(uint32_t* target) const noexcept
      {
        std::copy(data_, data_ + 8, target);
      }

    private:
      uint32_t data_[8];
    };

    Mixer m(value);
    aa_ = bb_ = cc_ = 0;

    for (int i = 0; i < 4; ++i)
    {
      m.mix();
    }

    for (size_t i = 0; i < SIZE; i += 8)
    {
      if (use_rand)
      {
        m.add(random_ + i);
      }
      m.mix();
      m.copy_to(state_ + i);
    }

    if (use_rand)
    {
      for (size_t i = 0; i < SIZE; i += 8)
      {
        m.add(state_ + i);
        m.mix();
        m.copy_to(state_ + i);
      }
    }

    reinit_();
  }
}

#endif
