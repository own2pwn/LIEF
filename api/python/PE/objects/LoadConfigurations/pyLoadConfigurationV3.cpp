/* Copyright 2017 R. Thomas
 * Copyright 2017 Quarkslab
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "pyPE.hpp"

#include "LIEF/visitors/Hash.hpp"
#include "LIEF/PE/LoadConfigurations.hpp"

#include <string>
#include <sstream>

template<class T>
using getter_t = T (LoadConfigurationV3::*)(void) const;

template<class T>
using setter_t = void (LoadConfigurationV3::*)(T);

void init_PE_LoadConfigurationV3_class(py::module& m) {
  py::class_<LoadConfigurationV3, LoadConfigurationV2>(m, "LoadConfigurationV3")
    .def(py::init<>())

    .def_property("guard_address_taken_iat_entry_table",
        static_cast<getter_t<uint64_t>>(&LoadConfigurationV3::guard_address_taken_iat_entry_table),
        static_cast<setter_t<uint64_t>>(&LoadConfigurationV3::guard_address_taken_iat_entry_table),
        "")

    .def_property("guard_address_taken_iat_entry_count",
        static_cast<getter_t<uint64_t>>(&LoadConfigurationV3::guard_address_taken_iat_entry_count),
        static_cast<setter_t<uint64_t>>(&LoadConfigurationV3::guard_address_taken_iat_entry_count),
        "")

    .def_property("guard_long_jump_target_table",
        static_cast<getter_t<uint64_t>>(&LoadConfigurationV3::guard_long_jump_target_table),
        static_cast<setter_t<uint64_t>>(&LoadConfigurationV3::guard_long_jump_target_table),
        "")

    .def_property("guard_long_jump_target_count",
        static_cast<getter_t<uint64_t>>(&LoadConfigurationV3::guard_long_jump_target_count),
        static_cast<setter_t<uint64_t>>(&LoadConfigurationV3::guard_long_jump_target_count),
        "")

    .def("__eq__", &LoadConfigurationV3::operator==)
    .def("__ne__", &LoadConfigurationV3::operator!=)
    .def("__hash__",
        [] (const LoadConfigurationV3& config) {
          return LIEF::Hash::hash(config);
        })


    .def("__str__", [] (const LoadConfigurationV3& config)
        {
          std::ostringstream stream;
          stream << config;
          std::string str = stream.str();
          return str;
        });


}
