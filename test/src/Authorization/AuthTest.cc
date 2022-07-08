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

        static std::string BucketName = "bucket";
        static std::string ObjectName = "object";

        TEST_F(AuthTest, SignHeaderV1Test)
        {
            // sign header test
            std::string FileNametoSave = Config::GetDataPath() + "sign.txt";

            ClientConfiguration conf;
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
            OssClient client = OssClient::Builder().endpoint(Config::Endpoint)
                                                   .configuration(conf)
                                                   .credentialsProvider(std::make_shared<SimpleCredentialsProvider>(Config::AccessKeyId, Config::AccessKeySecret))
                                                   .authVersion("4.0")
                                                   .region("region")
                                                   .cloudBoxId("cloudBoxId")
                                                   .build<OssClient>();

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
   }
}