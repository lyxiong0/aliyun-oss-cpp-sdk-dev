/*
 * Copyright 2009-2017 Alibaba Cloud All rights reserved.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

<<<<<<< HEAD:sdk/src/auth/AuthSignerV1.h
#include "AuthSigner.h"
=======
#include "Signer.h"
#include <ctime>
>>>>>>> 84f2ef4 (support builder pattern for OssClient.):sdk/src/auth/HmacSha256Signer.h

namespace AlibabaCloud
{
namespace OSS
{
<<<<<<< HEAD:sdk/src/auth/AuthSignerV1.h

    class  AuthSignerV1 : public AuthSigner
    {
    public:
        virtual ~AuthSignerV1() = default;
        virtual bool signRequest(HttpRequest &request, const AuthSignerParam& param) const override;
=======
    class HmacSha256Signer : public Signer
    {
    public:
        HmacSha256Signer();
        ~HmacSha256Signer();

        virtual byteArray generate(const byteArray &src, const std::string &secret)const override;
>>>>>>> 84f2ef4 (support builder pattern for OssClient.):sdk/src/auth/HmacSha256Signer.h
    };
}
}
