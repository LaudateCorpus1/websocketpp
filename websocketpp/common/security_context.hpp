/*
 * Copyright (c) 2014, Peter Thorson. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of the WebSocket++ Project nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL PETER THORSON BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#ifndef WEBSOCKETPP_COMMON_SECURITY_CONTEXT_HPP
#define WEBSOCKETPP_COMMON_SECURITY_CONTEXT_HPP

#include <websocketpp/common/memory.hpp>
#include <string>

#ifdef __APPLE__
#include <TargetConditionals.h>
#endif

#ifdef _WIN32
#include <winapifamily.h>

#if WINAPI_FAMILY_PARTITION(WINAPI_PARTITION_DESKTOP)
#define WEBSOCKETPP_WIN32
#endif // WINAPI_FAMILY_PARTITION

#endif // _WIN32

#ifdef WEBSOCKETPP_WIN32

#include <websocketpp/common/string_utils.hpp>
#include <websocketpp/base64/base64.hpp>

#define SECURITY_WIN32

#include <sspi.h>

#define SEC_SUCCESS(Status) ((Status) >= 0)

#pragma comment(lib, "Secur32.lib")

namespace websocketpp {
namespace lib {
namespace security {
class SecurityContext
{
public:
    typedef lib::shared_ptr<SecurityContext> Ptr;

    static SecurityContext::Ptr build(const std::string& proxyName, const std::string& authScheme) {
        return  lib::make_shared<SecurityContext>(proxyName, authScheme);
    }

    SecurityContext(const std::string& proxyName, const std::string& authScheme) :
        proxyName(proxyName), authScheme(authScheme)
    {
        TimeStamp           Lifetime;
        SECURITY_STATUS     ss;

        ss = ::AcquireCredentialsHandleA(
            NULL,
            (SEC_CHAR *)authScheme.c_str(),
            SECPKG_CRED_OUTBOUND,
            NULL,
            NULL,
            NULL,
            NULL,
            &hCred,
            &Lifetime);

        if (!(SEC_SUCCESS(ss)))
        {
            return;
        }

        freeCredentials = true;
    }
    ~SecurityContext()
    {
        if (freeCredentials) {
            ::FreeCredentialsHandle(&hCred);
        }
    }

    bool nextAuthToken(const std::string& challenge)
    {
        TimeStamp           Lifetime;
        SECURITY_STATUS     ss;
        SecBufferDesc       OutBuffDesc;
        SecBuffer           OutSecBuff;
        ULONG               ContextAttributes;

        OutBuffDesc.ulVersion = SECBUFFER_VERSION;
        OutBuffDesc.cBuffers = 1;
        OutBuffDesc.pBuffers = &OutSecBuff;

        OutSecBuff.cbBuffer = 0;
        OutSecBuff.BufferType = SECBUFFER_TOKEN;
        OutSecBuff.pvBuffer = 0;

        std::string target;

        if (websocketpp::lib::string_utils::icompare(authScheme, "Negotiate"))
            target = "http/" + proxyName; // Service Principle Name

        if (challenge.empty())
        {
            ss = ::InitializeSecurityContextA(
                &hCred,
                NULL,
                (SEC_CHAR *)target.c_str(), //.c_str(), // pszTarget,
                ISC_REQ_ALLOCATE_MEMORY, //ISC_REQ_CONFIDENTIALITY ,
                0,
                SECURITY_NETWORK_DREP, //SECURITY_NATIVE_DREP,
                NULL,
                0,
                &hContext,
                &OutBuffDesc,
                &ContextAttributes,
                &Lifetime);
        }
        else
        {
            auto decodedChallenge = base64_decode(challenge);

            SecBufferDesc     InBuffDesc;
            SecBuffer         InSecBuff;

            InBuffDesc.ulVersion = 0;
            InBuffDesc.cBuffers = 1;
            InBuffDesc.pBuffers = &InSecBuff;

            InSecBuff.cbBuffer = (unsigned long)decodedChallenge.size();
            InSecBuff.BufferType = SECBUFFER_TOKEN;
            InSecBuff.pvBuffer = (BYTE *)&decodedChallenge[0];

            ss = ::InitializeSecurityContextA(
                &hCred,
                &hContext,
                (SEC_CHAR *)target.c_str(),
                ISC_REQ_ALLOCATE_MEMORY, //ISC_REQ_CONFIDENTIALITY ,
                0,
                SECURITY_NETWORK_DREP, // SECURITY_NATIVE_DREP,
                &InBuffDesc,
                0,
                &hContext,
                &OutBuffDesc,
                &ContextAttributes,
                &Lifetime);
        }

        if ((SEC_I_COMPLETE_NEEDED == ss) || (SEC_I_COMPLETE_AND_CONTINUE == ss))
        {
            ss = ::CompleteAuthToken(&hContext, &OutBuffDesc);

            if (!SEC_SUCCESS(ss))
            {
                return false;
            }
        }

        if (!OutSecBuff.pvBuffer)
        {
            return false;
        }

        updatedToken = base64_encode((const unsigned char*)OutSecBuff.pvBuffer, (size_t)OutSecBuff.cbBuffer);

        ::FreeContextBuffer(OutSecBuff.pvBuffer);

        bool continueAuthFlow = ((SEC_I_CONTINUE_NEEDED == ss) || (SEC_I_COMPLETE_AND_CONTINUE == ss));

        return continueAuthFlow;
    }

    std::string getUpdatedToken() const
    {
        return updatedToken;
    }

private:
    SecHandle         hContext;
    CredHandle        hCred;
    std::string       proxyName;
    std::string       authScheme;
    std::string       updatedToken;

    bool              freeCredentials = false;
};
}       // security
}           // lib
}               // websocket

#elif defined(__APPLE__) && TARGET_OS_OSX // WEBSOCKETPP_WIN32

#include <GSS/GSS.h> // the library that lets us request kerberos tokens - https://tools.ietf.org/html/rfc2744
#include <Security/Security.h>

namespace websocketpp {
namespace lib {
namespace security {
class SecurityContext
{
public:
    typedef lib::shared_ptr<SecurityContext> Ptr;

    static Ptr build(const std::string& proxyName, const std::string& authScheme) {
        return  lib::make_shared<SecurityContext>(proxyName, authScheme);

    }

    SecurityContext(const std::string& proxyName, const std::string& authScheme) : m_proxyName(proxyName), m_authScheme(authScheme) {

        auto index = m_proxyName.find("://");
        if (index != std::string::npos) {
            m_proxyName = m_proxyName.substr(index + 3);
        }
        index = m_proxyName.find(":");
        if (index != std::string::npos) {
            m_proxyName = m_proxyName.substr(0, index);
        }
    }

    bool nextAuthToken(const std::string& challenge) {
        struct negotiatedata {
            enum { GSS_AUTHNONE, GSS_AUTHRECV, GSS_AUTHSENT } state;
            OM_uint32 status;
            gss_ctx_id_t context;
            gss_name_t server_name;
            gss_buffer_desc output_token;
        };

        struct negotiatedata neg_ctx = {};
        OM_uint32 major_status, minor_status;
        gss_buffer_desc spn_token = GSS_C_EMPTY_BUFFER;
        gss_buffer_desc input_token = GSS_C_EMPTY_BUFFER;
        gss_buffer_desc output_token = GSS_C_EMPTY_BUFFER;

        // SPN format for GSS API - https://docs.oracle.com/cd/E19683-01/816-1331/overview-6/index.html - Section principal name
        std::string spn = std::string("HTTP@").append(m_proxyName);
        spn_token.value = (void*)spn.c_str();
        spn_token.length = spn.length();

        // https://docs.oracle.com/cd/E19683-01/816-1331/overview-6/index.html - Section Names
        major_status = gss_import_name(&minor_status, &spn_token,
            GSS_C_NT_HOSTBASED_SERVICE,
            &neg_ctx.server_name);
        if (GSS_ERROR(major_status)) {
            std::stringstream ss;
            ss << "Cannot import SPN name: " << major_status;
            return false;
        }

        input_token.length = 0;
        gss_cred_id_t credentials = GSS_C_NO_CREDENTIAL; // default credentials will be used at OS's discretion, no need to supply from outside
        OM_uint32 req_flags = GSS_C_REPLAY_FLAG; // https://docs.oracle.com/cd/E19683-01/816-1331/6m7oo9sn5/index.html#overview-75
        OM_uint32* ret_flags = NULL;
        // https://docs.oracle.com/cd/E19683-01/816-1331/overview-6/index.html - Section Context Establishment
        major_status = gss_init_sec_context(
            &minor_status,
            credentials,
            &neg_ctx.context,
            neg_ctx.server_name,
            gss_mech_spnego,
            req_flags,
            0, /* time_req */
            GSS_C_NO_CHANNEL_BINDINGS, //https://docs.oracle.com/cd/E19683-01/816-1331/6m7oo9sn5/index.html#overview-52
            &input_token,
            NULL, /* actual_mech_type */
            &output_token,
            ret_flags,
            NULL /* time_rec */
        );
        if (GSS_ERROR(major_status)) {
            std::stringstream ss;
            ss << "Error initializing security context: " << major_status;
            return false;
        }

        CFDataRef data = CFDataCreate(NULL, (UInt8*)output_token.value, output_token.length);
        CFErrorRef error = NULL;
        SecTransformRef encoder = SecEncodeTransformCreate(kSecBase64Encoding, &error);
        SecTransformSetAttribute(encoder, kSecTransformInputAttributeName, data, &error);
        CFDataRef encodedData = (CFDataRef)SecTransformExecute(encoder, &error);
        CFStringRef token = CFStringCreateFromExternalRepresentation(NULL, encodedData, kCFStringEncodingUTF8);

        //NSString* encodedStr = [data base64EncodedStringWithOptions:0];
        //const char* encodedCstr = [encodedStr cStringUsingEncoding:NSUTF8StringEncoding];
        m_token = CFStringGetCStringPtr(token, kCFStringEncodingUTF8);;

        gss_release_buffer(&minor_status, &output_token);
        gss_delete_sec_context(&minor_status, &neg_ctx.context, GSS_C_NO_BUFFER);
        gss_release_name(&minor_status, &neg_ctx.server_name);

        return true;
    }
    std::string getUpdatedToken() const { return m_token; }

private:
    std::string m_proxyName;
    std::string m_authScheme;
    std::string m_token;
};
}       // security
}       // lib
}       // websocket

#else // WEBSOCKETPP_WIN32

namespace websocketpp {
namespace lib {
namespace security {

class SecurityContext {
public:
    typedef lib::shared_ptr<SecurityContext> Ptr;

    static Ptr build(const std::string& , const std::string& )  { return  Ptr(); }

    SecurityContext(const std::string& , const std::string& )   { }

    bool nextAuthToken(const std::string&)                      { return ""; }
    std::string getUpdatedToken() const                         { return ""; }
};
}       // security
}       // lib
}       // websocket


#endif // WEBSOCKETPP_WIN32
#endif // WEBSOCKETPP_COMMON_SECURITY_CONTEXT_HPP
