/*
 * Copyright 2013-2015 Raphael Bost, Raluca Ada Popa
 *
 * This file is part of ciphermed.

 *  ciphermed is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 * 
 *  ciphermed is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 * 
 *  You should have received a copy of the GNU General Public License
 *  along with ciphermed.  If not, see <http://www.gnu.org/licenses/>. 2
 *
 */

#pragma once

#include <stdexcept>
#include <assert.h>
#include <iostream>
#include <string>

#include <util/compiler.hh>
#include <sys/time.h>

class Timer {
 private:
    Timer(const Timer&) = delete;  /* no reason to copy timer objects */
    Timer(Timer &&) = delete;
    Timer &operator=(const Timer &) = delete;

 public:
    Timer() { lap(); }

    //microseconds
    uint64_t lap() {
        uint64_t t0 = start;
        uint64_t t1 = cur_usec();
        start = t1;
        return t1 - t0;
    }

    //milliseconds
    double lap_ms() {
        return ((double)lap()) / 1000.0;
    }

 private:
    static uint64_t cur_usec() {
        struct timeval tv;
        gettimeofday(&tv, 0);
        return ((uint64_t)tv.tv_sec) * 1000000 + tv.tv_usec;
    }

    uint64_t start;
};

class ScopedTimer {
public:
    ScopedTimer(const std::string &m) : m_(m) {}

    ScopedTimer(const ScopedTimer&) = delete;
    ScopedTimer(ScopedTimer &&) = delete;
    ScopedTimer &operator=(const ScopedTimer &) = delete;

    ~ScopedTimer()
    {
        const double e = t_.lap_ms();
        std::cerr << "region " << m_ << " took " << e << " ms" << std::endl;
    }

private:
    std::string m_;
    Timer t_;
};

class ResumableTimer {
public:
    ResumableTimer(const std::string &m) : m_(m), total_time_ms_(0), is_running_(true), t_() {}
    ResumableTimer(const ResumableTimer&) = delete;
    ResumableTimer(ResumableTimer &&) = delete;
    ResumableTimer &operator=(const ResumableTimer &) = delete;

    void restart()
    {
        total_time_ms_ = 0.;
        is_running_ = true;
        t_.lap();
    }
    
    void pause()
    {
        total_time_ms_ += t_.lap_ms();
        is_running_ = false;
    }
    
    void resume()
    {
        is_running_ = true;
        t_.lap();
    }
    
    double get_elapsed_time()
    {
        if (is_running_) {
            return total_time_ms_+t_.lap_ms();
        }
        return total_time_ms_;
    }
    
    ~ResumableTimer()
    {
        if (is_running_) {
            total_time_ms_ += t_.lap_ms();
        }
        
        std::cerr << "region " << m_ << " took " << total_time_ms_ << " ms" << std::endl;
    }

private:
    std::string m_;
    double total_time_ms_;
    bool is_running_;

    Timer t_;
};

class FullBenchTimer {
public:
    FullBenchTimer(const std::string &m) : m_(m), comp_time_ms_(0), net_time_ms_(0), is_running_(true), t_() {}
    FullBenchTimer(const ResumableTimer&) = delete;
    FullBenchTimer(ResumableTimer &&) = delete;
    FullBenchTimer &operator=(const ResumableTimer &) = delete;

    void restart()
    {
        comp_time_ms_ = 0.;
        net_time_ms_ = 0.;
        is_running_ = true;
        t_.lap();
    }

    void pause()
    {
        comp_time_ms_ += t_.lap_ms();
        is_running_ = false;
    }

    void resume()
    {
        net_time_ms_ += t_.lap_ms();
        is_running_ = true;
    }

    double get_elapsed_comp_time()
    {
        if (is_running_) {
            return comp_time_ms_+t_.lap_ms();
        }
        return comp_time_ms_;
    }

    double get_elapsed_net_time()
    {
        if (!is_running_) {
            return net_time_ms_+t_.lap_ms();
        }
        return net_time_ms_;
    }

    ~FullBenchTimer()
    {
        if (is_running_) {
            comp_time_ms_ += t_.lap_ms();
        } else {
            net_time_ms_ += t_.lap_ms();
        }

        std::cerr << "region " << m_ << " took " << comp_time_ms_ << " ms (computation), " << net_time_ms_ << " ms (network)" << std::endl;
    }

private:
    std::string m_;
    double comp_time_ms_;
    double net_time_ms_;
    bool is_running_;

    Timer t_;
};