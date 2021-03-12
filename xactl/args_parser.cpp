/*
 * BSD 2-Clause License
 * 
 * Copyright (c) 2021, Amin Saba
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 
 * 1. Redistributions of source code must retain the above copyright notice, this
 *    list of conditions and the following disclaimer.
 * 
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <iostream>
#include <map>
#include <vector>
#include <exception>
#include <queue>
#include <functional>
#include <string>
#include <sstream>

#include <getopt.h>

using namespace std::literals;

#include "args_parser.hpp"

incompatible_options_t
create_illegal_combs(incompatible_options_t options_incompatible)
{
	return options_incompatible;
}

options_spec_t
create_options_spec(options_short_spec_t short_switch_specs)
{
	options_spec_t switch_opts;

	for (auto const &t: short_switch_specs) {
		// C++17
		// auto [flag, prio, name, has_arg, auth_func, op_func] = t; 
		auto flag = std::get<0>(t);
		auto prio = std::get<1>(t);
		auto name = std::get<2>(t);
		auto has_arg = std::get<3>(t);
		auto auth_func = std::get<4>(t);
		auto op_func = std::get<5>(t);
		switch_opts.insert(
			{
				flag,
				(option_attrs){
					prio,
					name,
					has_arg == kHasArg ? required_argument : no_argument,
					false,
					auth_func,
					op_func
				}
			});
	}

	return switch_opts;
}

void
args_parser(int argc, char *argv[],
				options_spec_t &switch_opts,
				incompatible_options_t &options_incompatible)
{
	/**
	 * The priority queue used to process active switches in order of priority.
	 */
	auto attrs_cmp = [](auto left, auto right) { return left->priority > right->priority; };
	std::priority_queue<option_attrs*, std::vector<option_attrs*>, decltype(attrs_cmp)> attrs_pq(attrs_cmp);

	/**
	 * Prepare the struct option array and short options string to pass
	 * to getopt_long.
	 * The option array is built using the contents of the switch_opts
	 * map defined above.
	 */
	option *long_options = (option*)malloc(sizeof(option) * switch_opts.size());
	if (long_options == nullptr)
	{
		throw options_error{"Failed to allocate long_options: "s +
							std::string{__func__}};
	}
	std::string shortopts = "+";
	for (auto &kv: switch_opts) {
		int i = 0;
		long_options[i].flag = NULL;
		long_options[i].val = kv.first;
		long_options[i].name = kv.second.name.c_str();
		long_options[i].has_arg = kv.second.has_arg;
		shortopts += long_options[i].val;
		if (long_options[i].has_arg != no_argument)
			shortopts += ":";
		i++;
	}

	int opt, option_index = 0;
#ifdef USE_LONG_OPTS
	while ((opt = getopt_long(argc, argv, shortopts.c_str(), long_options,
								&option_index)) != -1) {
#else
	while ((opt = getopt(argc, argv, shortopts.c_str())) != -1) {
#endif
		/**
		 * Handle error cases
		 */
		switch (opt)
		{
		case 0:
			if (long_options[option_index].flag != 0)
				break;
			std::cerr << "option " << long_options[option_index].name;
			if (optarg)
				std::cerr << " with arg " << optarg;
			std::cerr << std::endl;
			break;

		case ':':
			std::cerr << "option needs a value" << std::endl;
			break;

		case '?':
			std::cerr << "parsing of command line options failed."
						<< std::endl;
			exit(1);
			break;
		}

		/**
		 * Find the requested option attributes and put it
		 * in the priority queue for later processing.
		 */
		auto switch_entry = switch_opts.find(opt);
		if (switch_entry != switch_opts.end()) {
			auto& opt_attr = switch_entry->second;
			opt_attr.is_set = true;
			if (optarg)
				opt_attr.arg = std::string{optarg};
			attrs_pq.push(&opt_attr);
		}
	}


	/**
	 * Run some sanity checks on the set options and arguments
	 */
	for (auto &constraint: options_incompatible) {
		auto key1 = std::get<0>(constraint);
		auto key2 = std::get<1>(constraint);

		auto switch_entry1 = switch_opts.find(key1);
		auto switch_entry2 = switch_opts.find(key2);


		if (switch_entry1->second.is_set && switch_entry2->second.is_set) {
			std::ostringstream err_msg_stream;
			err_msg_stream << "Switches -" << key1
							<< " and -" << key2 << " are incompatible.";
			throw options_error{err_msg_stream.str()};
		}
	}

	/**
	 * Now process all set options in order of priority
	 */
	while (!attrs_pq.empty()) {
		std::function<void(void)> auth_func;
		void (*fop)(void);
		void (*fopa)(std::string);
		std::string arg;
		option_attrs *switch_entry;

		switch_entry = attrs_pq.top();
		attrs_pq.pop();

		auth_func = switch_entry->auth_func;
		if (auth_func)
			auth_func();
		if (switch_entry->has_arg) {
			arg = switch_entry->arg;
			fopa = (decltype(fopa))switch_entry->op;
			fopa(arg);
		} else {
			fop = (decltype(fop))switch_entry->op;
			fop();
		}
	}

	free(long_options);
}
