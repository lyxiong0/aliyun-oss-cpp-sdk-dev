#include <gtest/gtest.h>
#include <alibabacloud/oss/OssClient.h>
#include "../Config.h"
#include "../../../sdk/src/auth/SignGeneratorV1.h"
#include "../../../sdk/src/auth/SignGeneratorV4.h"
#include <alibabacloud/oss/OssRequest.h>
#include <fstream>

namespace AlibabaCloud
{
    namespace OSS
    {

        class AuthTest : public ::testing::Test
        {
        protected:
            AuthTest()
            {
            }

            ~AuthTest() override
            {
            }

            void SetUp() override
            {
            }

            void TearDown() override
            {
            }
        };

        static std::string BucketName = "signv4";
        static std::string ObjectName = "sign.txt";

        TEST_F(AuthTest, SignHeaderV1Test)
        {
            // sign header test
            std::string FileNametoSave = Config::GetDataPath() + "sign.txt";

            ClientConfiguration conf;
            // conf.authVersion = "4.0";
            // conf.authAlgorithm = "HMAC-SHA256";
            OssClient client(Config::Endpoint, Config::AccessKeyId, Config::AccessKeySecret, conf);
            GetObjectRequest request(BucketName, ObjectName);

            auto outcome = client.GetObject(request);

            if (outcome.isSuccess())
            {
                std::cout << "GetObjectToFile success" << outcome.result().Metadata().ContentLength() << std::endl;
            }
            else
            {
                std::cout << "GetObjectToFile fail"
                          << ",code:" << outcome.error().Code() << ",message:" << outcome.error().Message() << ",requestId:" << outcome.error().RequestId() << std::endl;
            }
            EXPECT_EQ(outcome.isSuccess(), true);
        }

        TEST_F(AuthTest, PresignV1Test)
        {
            ClientConfiguration conf;
            // conf.authVersion = "1.0";
            // conf.authAlgorithm = "HMAC-SHA1";
            OssClient client(Config::Endpoint, Config::AccessKeyId, Config::AccessKeySecret, conf);

            std::time_t t = std::time(nullptr) + 1200;
            auto genOutcome = client.GeneratePresignedUrl(BucketName, ObjectName, t, Http::Get);

            EXPECT_EQ(genOutcome.isSuccess(), true);
            std::cout << "GeneratePresignedUrl success, Gen url:" << genOutcome.result().c_str() << std::endl;

            auto outcome = client.GetObjectByUrl(genOutcome.result());

            if (!outcome.isSuccess())
            {
                std::cerr << "GetObjectByUrl fail"
                          << ",code:" << outcome.error().Code() << ",message:" << outcome.error().Message() << ",requestId:" << outcome.error().RequestId() << std::endl;
            }

            EXPECT_EQ(outcome.isSuccess(), true);
        }

        TEST_F(AuthTest, SignV4OSSTest)
        {
            // no clound-box and addtional header
            ClientConfiguration conf;
            conf.authVersion = "4.0";
            OssClient client(Config::Endpoint, Config::AccessKeyId, Config::AccessKeySecret, conf);
            client.setProduct("oss");
            client.setRegion("cn-hangzhou");
            // client.setCloudBoxId("cloudboxtest");
            // client.setAdditionalHeaders(conf.additionalHeaders);

            GetObjectRequest request(BucketName, ObjectName);

            auto outcome = client.GetObject(request);

            if (outcome.isSuccess())
            {
                std::cout << "GetObjectToFile success" << outcome.result().Metadata().ContentLength() << std::endl;
            }
            else
            {
                std::cout << "GetObjectToFile fail"
                          << ",code:" << outcome.error().Code() << ",message:" << outcome.error().Message() << ",requestId:" << outcome.error().RequestId() << std::endl;
            }
            EXPECT_EQ(outcome.isSuccess(), false);
        }

        TEST_F(AuthTest, SignV4CloudBoxTest)
        {
            // no addtional header
            ClientConfiguration conf;
            conf.authVersion = "4.0";
            OssClient client(Config::Endpoint, Config::AccessKeyId, Config::AccessKeySecret, conf);
            client.setRegion("cn-hangzhou");
            client.setCloudBoxId("cloudboxtest");
            client.setProduct("oss-cloud");
            // client.setAdditionalHeaders(conf.additionalHeaders);

            GetObjectRequest request(BucketName, ObjectName);

            auto outcome = client.GetObject(request);

            if (outcome.isSuccess())
            {
                std::cout << "GetObjectToFile success" << outcome.result().Metadata().ContentLength() << std::endl;
            }
            else
            {
                std::cout << "GetObjectToFile fail"
                          << ",code:" << outcome.error().Code() << ",message:" << outcome.error().Message() << ",requestId:" << outcome.error().RequestId() << std::endl;
            }
            EXPECT_EQ(outcome.isSuccess(), false);
        }

        TEST_F(AuthTest, SignV4AdditionalTest)
        {
            ClientConfiguration conf;
            conf.authVersion = "4.0";
            conf.additionalHeaders.emplace_back("host");
            OssClient client(Config::Endpoint, Config::AccessKeyId, Config::AccessKeySecret, conf);
            client.setRegion("cn-hangzhou");
            client.setCloudBoxId("cloudboxtest");
            client.setProduct("oss-cloud");
            client.setAdditionalHeaders(conf.additionalHeaders);

            GetObjectRequest request(BucketName, ObjectName);

            auto outcome = client.GetObject(request);

            if (outcome.isSuccess())
            {
                std::cout << "GetObjectToFile success" << outcome.result().Metadata().ContentLength() << std::endl;
            }
            else
            {
                std::cout << "GetObjectToFile fail"
                          << ",code:" << outcome.error().Code() << ",message:" << outcome.error().Message() << ",requestId:" << outcome.error().RequestId() << std::endl;
            }
            EXPECT_EQ(outcome.isSuccess(), false);
        }

        

        TEST_F(AuthTest, SignV4Test) {
            std::shared_ptr<HttpRequest> request = std::make_shared<HttpRequest>(Http::Get);
            ClientConfiguration conf;
            conf.authVersion = "4.0";
            Credentials credentials(Config::AccessKeyId, Config::AccessKeySecret, "security-token");

            ParameterCollection parameters;
            parameters["notInParamtersToSign"] = "Invalid";
            parameters["worm"] = "Valid";
            parameters["acl"] = "Valid2";

            SignParam signParam(conf, "/signv4/sign.txt", parameters, credentials, 0);
            // signParam.setCloudBoxId(cloudBoxId_);
            signParam.setRegion("cn-hangzhou");
            signParam.setProduct("oss");

            // addHeaders test
            std::shared_ptr<SignGeneratorV4> signGenerator = std::make_shared<SignGeneratorV4>("HMAC-SHA256");
            signGenerator->addHeaders(request, signParam);

            std::time_t t = std::time(nullptr);
            EXPECT_EQ(request->hasHeader("x-oss-date"), true);
            EXPECT_STREQ(request->Header("x-oss-date").c_str(), ToUtcTimeWithoutMill(t).c_str());
            EXPECT_EQ(request->hasHeader("x-oss-security-token"), true);
            EXPECT_STREQ(request->Header("x-oss-security-token").c_str(), "security-token");
            EXPECT_EQ(request->hasHeader("x-oss-content-sha256"), true);
            EXPECT_STREQ(request->Header("x-oss-content-sha256").c_str(), "UNSIGNED-PAYLOAD");

            // genCanonicalReuqest test
            std::string canonical = signGenerator->genCanonicalReuqest(Http::MethodToString(request->method()), signParam.resource_, request->Headers(), signParam.params_, signParam.additionalHeaders_);
            std::string realCanonical = "GET\n/signv4/sign.txt\nworm=valid&acl=valid2\n";
            // EXPECT_STREQ(canonical.c_str(), )
            std::cerr << canonical << std::endl;
        }
    }
}