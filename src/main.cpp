#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string>
#include <vector>

struct DNSHeader {
    uint16_t id;
    uint16_t flags;    // qr(1) + opcode(4) + aa(1) + tc(1) + rd(1) + ra(1) + z(3) + rcode(4)
    uint16_t qdcount; 
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
};

struct DNSQuestion {
    std::vector<uint8_t> name_as_vector;
    uint16_t type;
    uint16_t class_;
};

struct DNSAnswer {
    std::vector<uint8_t> name_as_vector;
    uint16_t type;
    uint16_t class_;
    uint32_t ttl;
    uint16_t rdlength;
    std::vector<uint8_t> rdata;
};

struct DNSAuthority {
};

struct DNSAdditional {
};

struct DNSmessage {
    DNSHeader header;
    DNSQuestion question;
    DNSAnswer answer;
    DNSAuthority authority;
    DNSAdditional additional;
};

std::vector<uint8_t> encodeDomainName(const std::string& domain) {
    std::vector<uint8_t> result;
    size_t start = 0;
    size_t pos = 0;
    while ((pos = domain.find('.', start)) != std::string::npos) {
        std::string label = domain.substr(start, pos - start);
        result.push_back(static_cast<uint8_t>(label.size()));
        for (char c : label) result.push_back(static_cast<uint8_t>(c));
        start = pos + 1;
    }
    std::string label = domain.substr(start);
    result.push_back(static_cast<uint8_t>(label.size()));
    for (char c : label) result.push_back(static_cast<uint8_t>(c));
    result.push_back(0);
    return result;
}

std::vector<uint8_t> decompressDomainName(const char* buffer, size_t bufferSize, size_t& offset) {
    std::vector<uint8_t> result;
    bool jumped = false;
    size_t jumpOffset = 0;
    
    while (offset < bufferSize) {
        uint8_t length = static_cast<uint8_t>(buffer[offset]);
        //check for compression
        if ((length & 0xC0) == 0xC0) {
            if (offset + 1 >= bufferSize) break;
            uint16_t pointer = ((length & 0x3F) << 8) | static_cast<uint8_t>(buffer[offset + 1]);
            
            if (!jumped) {
                jumpOffset = offset + 2;
                jumped = true;
            }
            
            offset = pointer;
            continue;
        }
        
        if (length == 0) {
            result.push_back(0);
            offset++;
            break;
        }
        
        result.push_back(length);
        offset++;
        for (uint8_t i = 0; i < length && offset < bufferSize; i++) {
            result.push_back(static_cast<uint8_t>(buffer[offset++]));
        }
    }
    
    if (jumped) {
        offset = jumpOffset;
    }
    
    return result;
}

DNSQuestion parseQuestion(const char* buffer, size_t bufferSize, size_t& offset) {
    DNSQuestion question;
    
    question.name_as_vector = decompressDomainName(buffer, bufferSize, offset);
    
    if (offset + 2 <= bufferSize) {
        question.type = (static_cast<uint8_t>(buffer[offset]) << 8) | static_cast<uint8_t>(buffer[offset + 1]);
        offset += 2;
    }

    if (offset + 2 <= bufferSize) {
        question.class_ = (static_cast<uint8_t>(buffer[offset]) << 8) | static_cast<uint8_t>(buffer[offset + 1]);
        offset += 2;
    }
    
    return question;
}

DNSAnswer parseAnswer(const char* buffer, size_t bufferSize, size_t& offset) {
    DNSAnswer answer;
    answer.name_as_vector = decompressDomainName(buffer, bufferSize, offset);
    if (offset + 2 <= bufferSize) {
        answer.type = (static_cast<uint8_t>(buffer[offset]) << 8) | static_cast<uint8_t>(buffer[offset + 1]);
        offset += 2;
    }
    if (offset + 2 <= bufferSize) {
        answer.class_ = (static_cast<uint8_t>(buffer[offset]) << 8) | static_cast<uint8_t>(buffer[offset + 1]);
        offset += 2;
    }
    if (offset + 4 <= bufferSize) {
        answer.ttl = (static_cast<uint8_t>(buffer[offset]) << 24) |
                     (static_cast<uint8_t>(buffer[offset + 1]) << 16) |
                     (static_cast<uint8_t>(buffer[offset + 2]) << 8) |
                     static_cast<uint8_t>(buffer[offset + 3]);
        offset += 4;
    }
    if (offset + 2 <= bufferSize) {
        answer.rdlength = (static_cast<uint8_t>(buffer[offset]) << 8) | static_cast<uint8_t>(buffer[offset + 1]);
        offset += 2;
    }
    if (offset + answer.rdlength <= bufferSize) {
        answer.rdata.assign(buffer + offset, buffer + offset + answer.rdlength);
        offset += answer.rdlength;
    }
    return answer;
}

DNSHeader createResponseHeader(const DNSHeader& queryHeader, int qdcount = 0, int ancount = 0, int nscount = 0, int arcount = 0) {
    DNSHeader header;
    header.id = queryHeader.id;
    uint16_t queryFlags = ntohs(queryHeader.flags);
    uint16_t opcode = (queryFlags >> 11) & 0x0F;  // bits 11-14
    uint16_t rd = (queryFlags >> 8) & 0x01;       // bit 8
    
    uint16_t rcode = (opcode == 0) ? 0 : 4;
    
    // qr=1 (bit 15), opcode (bits 11-14), aa=0 (bit 10), tc=0 (bit 9), rd (bit 8)
    // ra=0 (bit 7), z=0 (bits 4-6), rcode (bits 0-3)
    uint16_t responseFlags = (1 << 15)
                           | (opcode << 11)
                           | (0 << 10)
                           | (0 << 9)
                           | (rd << 8)
                           | (0 << 7)
                           | (0 << 4)
                           | rcode;
    
    header.flags = htons(responseFlags);
    header.qdcount = htons(qdcount);
    header.ancount = htons(ancount);
    header.nscount = htons(nscount);
    header.arcount = htons(arcount);
    return header;
}

DNSQuestion createResponseQuestion(std::string domain_name, uint16_t qtype, uint16_t qclass) {
    DNSQuestion question;
    question.name_as_vector = encodeDomainName(domain_name);
    question.type = htons(qtype);
    question.class_ = htons(qclass);
    return question;
}

DNSAnswer createResponseAnswer(std::string domain_name, uint16_t atype, uint16_t aclass, uint32_t ttl, const std::vector<uint8_t>& rdata) {
    DNSAnswer answer;
    answer.name_as_vector = encodeDomainName(domain_name);
    answer.type = htons(atype);
    answer.class_ = htons(aclass);
    answer.ttl = htonl(ttl);
    answer.rdlength = htons(static_cast<uint16_t>(rdata.size()));
    answer.rdata = rdata;
    return answer;
}

void add_header_to_buffer(std::vector<uint8_t>& buffer, const DNSHeader& header) {
    const uint8_t* header_ptr = reinterpret_cast<const uint8_t*>(&header);
    buffer.insert(buffer.end(), header_ptr, header_ptr + sizeof(DNSHeader));
}

void add_question_to_buffer(std::vector<uint8_t>& buffer, const DNSQuestion& question) {
    buffer.insert(buffer.end(), question.name_as_vector.begin(), question.name_as_vector.end());
    const uint8_t* type_ptr = reinterpret_cast<const uint8_t*>(&question.type);
    buffer.push_back(type_ptr[0]);
    buffer.push_back(type_ptr[1]);
    const uint8_t* class_ptr = reinterpret_cast<const uint8_t*>(&question.class_);
    buffer.push_back(class_ptr[0]);
    buffer.push_back(class_ptr[1]);
}

void add_answer_to_buffer(std::vector<uint8_t>& buffer, const DNSAnswer& answer) {
    buffer.insert(buffer.end(), answer.name_as_vector.begin(), answer.name_as_vector.end());
    const uint8_t* type_ptr = reinterpret_cast<const uint8_t*>(&answer.type);
    buffer.push_back(type_ptr[0]);
    buffer.push_back(type_ptr[1]);
    const uint8_t* class_ptr = reinterpret_cast<const uint8_t*>(&answer.class_);
    buffer.push_back(class_ptr[0]);
    buffer.push_back(class_ptr[1]);
    const uint8_t* ttl_ptr = reinterpret_cast<const uint8_t*>(&answer.ttl);
    buffer.push_back(ttl_ptr[0]);
    buffer.push_back(ttl_ptr[1]);
    buffer.push_back(ttl_ptr[2]);
    buffer.push_back(ttl_ptr[3]);
    const uint8_t* rdlength_ptr = reinterpret_cast<const uint8_t*>(&answer.rdlength);
    buffer.push_back(rdlength_ptr[0]);
    buffer.push_back(rdlength_ptr[1]);
    buffer.insert(buffer.end(), answer.rdata.begin(), answer.rdata.end());
}

int main(int argc, char* argv[])
{
    std::cout << std::unitbuf;
    std::cerr << std::unitbuf;
    setbuf(stdout, NULL);

    std::string resolverIp;
    int resolverPort = 0;
    for (int i = 1; i < argc; i++) {
        if (std::string(argv[i]) == "--resolver" && i + 1 < argc) {
            std::string resolver = argv[i + 1];
            size_t colonPos = resolver.find(':');
            if (colonPos != std::string::npos) {
                resolverIp = resolver.substr(0, colonPos);
                resolverPort = std::stoi(resolver.substr(colonPos + 1));
            }
            break;
        }
    }
    
    bool useResolver = !resolverIp.empty() && resolverPort > 0;
    if (useResolver) {
        std::cout << "Using resolver: " << resolverIp << ":" << resolverPort << std::endl;
    }

    int udpSocket;
    struct sockaddr_in clientAddress;

    udpSocket = socket(AF_INET, SOCK_DGRAM, 0);
    if (udpSocket == -1)
    {
        std::cerr << "Socket creation failed: " << strerror(errno) << "..." << std::endl;
        return 1;
    }
    int reuse = 1;
    if (setsockopt(udpSocket, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse)) < 0)
    {
        std::cerr << "SO_REUSEPORT failed: " << strerror(errno) << std::endl;
        return 1;
    }

    sockaddr_in serv_addr = {
        .sin_family = AF_INET,
        .sin_port = htons(2053),
        .sin_addr = {htonl(INADDR_ANY)},
    };

    if (bind(udpSocket, reinterpret_cast<struct sockaddr *>(&serv_addr), sizeof(serv_addr)) != 0)
    {
        std::cerr << "Bind failed: " << strerror(errno) << std::endl;
        return 1;
    }

    int bytesRead;
    char buffer[512];
    socklen_t clientAddrLen = sizeof(clientAddress);
    while (true)
    {
        bytesRead = recvfrom(udpSocket, buffer, sizeof(buffer), 0, reinterpret_cast<struct sockaddr *>(&clientAddress), &clientAddrLen);
        if (bytesRead == -1)
        {
            perror("Error receiving data");
            break;
        }

        std::cout << "Received " << bytesRead << " bytes" << std::endl;

        // query header
        if (bytesRead < (int)sizeof(DNSHeader)) {
            std::cerr << "Packet too small" << std::endl;
            continue;
        }
        
        DNSHeader queryHeader;
        memcpy(&queryHeader, buffer, sizeof(DNSHeader));
        
        // number of questions
        uint16_t qdcount = ntohs(queryHeader.qdcount);

        // parse all questions
        size_t offset = sizeof(DNSHeader);
        std::vector<DNSQuestion> questions;
        for (uint16_t i = 0; i < qdcount; i++) {
            DNSQuestion q = parseQuestion(buffer, bytesRead, offset);
            questions.push_back(q);
        }

        // create response
        std::vector<uint8_t> responseBuffer;
        std::vector<DNSAnswer> answers;
        
        if (useResolver) {
            sockaddr_in resolverAddr;
            resolverAddr.sin_family = AF_INET;
            resolverAddr.sin_port = htons(resolverPort);
            inet_pton(AF_INET, resolverIp.c_str(), &resolverAddr.sin_addr);
            
            for (const auto& question : questions) {
                std::vector<uint8_t> forwardBuffer;
                
                DNSHeader forwardHeader;
                forwardHeader.id = queryHeader.id;
                forwardHeader.flags = htons(0);
                forwardHeader.qdcount = htons(1);
                forwardHeader.ancount = htons(0);
                forwardHeader.nscount = htons(0);
                forwardHeader.arcount = htons(0);
                add_header_to_buffer(forwardBuffer, forwardHeader);
                
                // add the question
                DNSQuestion fwdQuestion;
                fwdQuestion.name_as_vector = question.name_as_vector;
                fwdQuestion.type = htons(question.type);
                fwdQuestion.class_ = htons(question.class_);
                add_question_to_buffer(forwardBuffer, fwdQuestion);
                
                // send
                if (sendto(udpSocket, forwardBuffer.data(), forwardBuffer.size(), 0,
                          reinterpret_cast<struct sockaddr*>(&resolverAddr), sizeof(resolverAddr)) == -1) {
                    perror("Failed to forward to resolver");
                    continue;
                }
                
                // receive response from resolver
                char resolverBuffer[512];
                sockaddr_in resolverResponseAddr;
                socklen_t resolverAddrLen = sizeof(resolverResponseAddr);
                int resolverBytes = recvfrom(udpSocket, resolverBuffer, sizeof(resolverBuffer), 0,
                                             reinterpret_cast<struct sockaddr*>(&resolverResponseAddr), &resolverAddrLen);
                
                if (resolverBytes > 0) {
                    DNSHeader resolverHeader;
                    memcpy(&resolverHeader, resolverBuffer, sizeof(DNSHeader));
                    
                    uint16_t resQdcount = ntohs(resolverHeader.qdcount);
                    uint16_t resAncount = ntohs(resolverHeader.ancount);
                    
                    size_t resOffset = sizeof(DNSHeader);
                    for (uint16_t j = 0; j < resQdcount; j++) {
                        parseQuestion(resolverBuffer, resolverBytes, resOffset);
                    }
                    
                    for (uint16_t j = 0; j < resAncount; j++) {
                        DNSAnswer ans = parseAnswer(resolverBuffer, resolverBytes, resOffset);
                        answers.push_back(ans);
                    }
                }
            }
        } else {
            for (const auto& question : questions) {
                DNSAnswer answer;
                answer.name_as_vector = question.name_as_vector;
                answer.type = 1;
                answer.class_ = 1;
                answer.ttl = 60;
                answer.rdlength = 4;
                answer.rdata = {8, 8, 8, 8};
                answers.push_back(answer);
            }
        }
        
        // build response header
        DNSHeader header = createResponseHeader(queryHeader, qdcount, answers.size(), 0, 0);
        add_header_to_buffer(responseBuffer, header);
        
        // add question section
        for (const auto& queryQuestion : questions) {
            DNSQuestion responseQuestion;
            responseQuestion.name_as_vector = queryQuestion.name_as_vector;
            responseQuestion.type = htons(queryQuestion.type);
            responseQuestion.class_ = htons(queryQuestion.class_);
            add_question_to_buffer(responseBuffer, responseQuestion);
        }

        // add answer section
        for (const auto& ans : answers) {
            DNSAnswer responseAnswer;
            responseAnswer.name_as_vector = ans.name_as_vector;
            responseAnswer.type = htons(ans.type);
            responseAnswer.class_ = htons(ans.class_);
            responseAnswer.ttl = htonl(ans.ttl);
            responseAnswer.rdlength = htons(ans.rdlength);
            responseAnswer.rdata = ans.rdata;
            add_answer_to_buffer(responseBuffer, responseAnswer);
        }

        // send response
        if (sendto(udpSocket, responseBuffer.data(), responseBuffer.size(), 0, reinterpret_cast<struct sockaddr *>(&clientAddress), sizeof(clientAddress)) == -1)
        {
            perror("Failed to send response");
        }
    }

    close(udpSocket);

    return 0;
}
