/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2010 The Boeing Company
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation;
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Author: Gary Pei <guangyu.pei@boeing.com>
 */
#ifndef __INET_NIST - ERROR - RATE - MODEL_H
#define __INET_NIST    -ERROR - RATE - MODEL_H

//#include <stdint.h>
#include "WifiMode.h"
#include "IErrorModel.h"
#include "dsss-error-rate-model.h"

namespace inet {
namespace physicallayer {
/**
 * \ingroup wifi
 *
 * A model for the error rate for different modulations.  For OFDM modulation,
 * the model description and validation can be found in
 * http://www.nsnam.org/~pei/80211ofdm.pdf.  For DSSS modulations (802.11b),
 * the model uses the DsssErrorRateModel.
 */
class NistErrorRateModel : public IErrorModel
{
  public:

    NistErrorRateModel();
    virtual ~NistErrorRateModel();
    virtual double GetChunkSuccessRate(ModulationType mode, double snr, uint32_t nbits) const;

  private:
    double CalculatePe(double p, uint32_t bValue) const;
    double GetBpskBer(double snr) const;
    double GetQpskBer(double snr) const;
    double Get16QamBer(double snr) const;
    double Get64QamBer(double snr) const;
    double GetFecBpskBer(double snr, double nbits,
            uint32_t bValue) const;
    double GetFecQpskBer(double snr, double nbits,
            uint32_t bValue) const;
    double GetFec16QamBer(double snr, uint32_t nbits,
            uint32_t bValue) const;
    double GetFec64QamBer(double snr, uint32_t nbits,
            uint32_t bValue) const;
};
} // namespace physicallayer
} // namespace inet

#endif /* NIST_ERROR_RATE_MODEL_H */
