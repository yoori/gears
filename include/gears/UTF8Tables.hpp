#pragma once

#include <cstdint>
#include <gears/SubString.hpp>

namespace Gears::String
{
  namespace Detail
  {
    typedef const char Plane1Byte[64];
    typedef const char CodeUnit2Bytes[2];
    typedef const CodeUnit2Bytes Plane2Bytes[64];
    typedef const char CodeUnit4Bytes[4];
    typedef const CodeUnit4Bytes Plane4Bytes[64];
    typedef const uint64_t Plane2Bits[2];
  }


  namespace ToLower
  {
    using namespace Detail;

    extern const char TABLE_1[128];

    extern const Plane2Bytes TABLE_2[19];

    extern const Plane4Bytes TABLE_3_E1[64];

    extern const Plane2Bytes TABLE_3_E2[64];

    extern const Plane2Bytes TABLE_3_EA[6];

    extern const char TABLE_3_EF[64];

    extern const CodeUnit2Bytes TABLE_3_SP_E2[32];

    extern const char TABLE_4_F0[64];
  }

  namespace ToUpper
  {
    using namespace Detail;

    extern const char TABLE_1[128];

    extern const Plane2Bytes TABLE_2[21];

    extern const Plane4Bytes TABLE_3_E1[64];

    extern const Plane2Bytes TABLE_3_E2[64];

    extern const Plane2Bytes TABLE_3_EA[6];

    extern const char TABLE_3_EF[64];

    extern const char TABLE_4_F0_90[64];

    extern const char TABLE_4_F0_91[16];
  }

  namespace ToUniform
  {
    using namespace Detail;

    extern const char TABLE_1[128];

    extern const Plane2Bytes TABLE_2[21];

    extern const Plane4Bytes TABLE_3_E1[64];

    struct Table_3_E1_BF
    {
      SubString substr;
      size_t symbols;
    };
    extern const Table_3_E1_BF TABLE_3_E1_BF[64];

    extern const Plane2Bytes TABLE_3_E2[64];

    extern const Plane2Bytes TABLE_3_EA[6];

    extern const CodeUnit2Bytes TABLE_3_EF_AC[8];

    extern const char TABLE_3_EF_BC[32];

    extern const CodeUnit2Bytes TABLE_3_SP_E2[32];

    extern const char TABLE_4_F0[64];
  }

  namespace ToSimplify
  {
    using namespace Detail;

    extern const char TABLE_1[128];

    extern const Plane2Bytes TABLE_2[30];
    extern const SubString TABLE_2_[12];

    extern const Plane2Bits TABLE_3_E0[32];
    extern const char TABLE_3_E0_[8];

    extern const Plane2Bits TABLE_3_E1_1[52];
    extern const Plane2Bytes TABLE_3_E1_2[12];
    extern const SubString TABLE_3_E1_2_[13];

    extern const Plane1Byte TABLE_3_E2_1[5];
    extern const SubString TABLE_3_E2_1_[26];
    extern const Plane4Bytes TABLE_3_E2_2[2];
    extern const Plane4Bytes TABLE_3_E2_3[3];
    extern const Plane4Bytes TABLE_3_E2_4[16];

    extern const Plane4Bytes TABLE_3_E3[16];
    extern const SubString TABLE_3_E3_[222];

    extern const Plane4Bytes TABLE_3_EA_1[7];
    extern const Plane2Bits TABLE_3_EA_2[16];
    extern const SubString TABLE_3_EA_2_[4];

    extern const Plane4Bytes TABLE_3_EF[28];
    extern const SubString TABLE_3_EF_[132];

    extern const Plane2Bits TABLE_4_F0_90_1[64];
    extern const Plane2Bytes TABLE_4_F0_90_2[1];

    extern const Plane2Bits TABLE_4_F0_91[29];

    extern const Plane2Bits TABLE_4_F0_96[24];

    extern const Plane2Bits TABLE_4_F0_9B[2];

    extern const Plane2Bits TABLE_4_F0_9D_1[16];
    extern const Plane2Bytes TABLE_4_F0_9D_2[16];

    extern const Plane2Bits TABLE_4_F0_9E_1[1];
    extern const Plane2Bytes TABLE_4_F0_9E_2[3];

    extern const Plane4Bytes TABLE_4_F0_9F[6];
    extern const SubString TABLE_4_F0_9F_[12];

    extern const Plane4Bytes TABLE_4_F0_AF[9];
  }
}
