#include "retriever.hpp"

void PRINT_BYTE_ARRAY_WRITE(
    FILE* file, void* mem, uint32_t len)
{
    if (!mem || !len) {
        fprintf(file, "\n( null )\n");
        return;
    }
    uint8_t* array = (uint8_t*)mem;
    fprintf(file, "%u bytes:\n{\n", len);
    uint32_t i = 0;
    for (i = 0; i < len - 1; i++) {
        fprintf(file, "0x%x, ", array[i]);
        if (i % 8 == 7)
            fprintf(file, "\n");
    }
    fprintf(file, "0x%x ", array[i]);
    fprintf(file, "\n}\n");
}

Retriever::Retriever(string fileName, RecvDecode*& recvDecodeObjTemp)
{
    recvDecodeObj_ = recvDecodeObjTemp;
    string newFileName = fileName.append(".d");
    retrieveFile_.open(newFileName, ofstream::out | ofstream::binary);
    Recipe_t tempRecipe = recvDecodeObj_->getFileRecipeHead();
    totalChunkNumber_ = tempRecipe.fileRecipeHead.totalChunkNumber;
}

Retriever::~Retriever()
{
    retrieveFile_.close();
    cerr << "Retriever : file close correct" << endl;
}

void Retriever::recvThread()
{
    RetrieverData_t newData;
    while (totalRecvNumber_ < totalChunkNumber_) {
        if (extractMQFromRecvDecode(newData)) {
            retrieveFile_.write(newData.logicData, newData.logicDataSize);
            // cerr << newData.logicData << endl;
            totalRecvNumber_++;
        }
    }
    cerr << "Retriever : job done, thread exit now" << endl;
    return;
}

bool Retriever::extractMQFromRecvDecode(RetrieverData_t& newData)
{
    return recvDecodeObj_->extractMQToRetriever(newData);
}
