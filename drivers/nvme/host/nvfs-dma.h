/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/*
 * Copyright (c) 2020 NVIDIA Corporation.
 */

#ifndef NVFS_DMA_H
#define NVFS_DMA_H

static blk_status_t nvme_pci_setup_prps(struct nvme_dev *dev,
                struct request *req, struct nvme_rw_command *cmnd);

static blk_status_t nvme_pci_setup_sgls(struct nvme_dev *dev,
                struct request *req, struct nvme_rw_command *cmd, int entries);

static bool nvme_nvfs_unmap_data(struct nvme_dev *dev, struct request *req)
{
        struct nvme_iod *iod = blk_mq_rq_to_pdu(req);
        enum dma_data_direction dma_dir = rq_dma_dir(req);
        const int last_prp = NVME_CTRL_PAGE_SIZE / sizeof(__le64) - 1;
        dma_addr_t dma_addr = iod->first_dma, next_dma_addr;

        if (iod->sg && !is_pci_p2pdma_page(sg_page(iod->sg)) &&
            !blk_integrity_rq(req) &&
            !iod->dma_len &&
            nvfs_ops != NULL) {

                int i, count;
                count = nvfs_ops->nvfs_dma_unmap_sg(dev->dev, iod->sg, iod->nents,
                                dma_dir);

                if (!count)
                        return false;

                if (iod->npages == 0)
                        dma_pool_free(dev->prp_small_pool, nvme_pci_iod_list(req)[0],
                                        dma_addr);

                for (i = 0; i < iod->npages; i++) {
                        void *addr = nvme_pci_iod_list(req)[i];

                        if (iod->use_sgl) {
                                struct nvme_sgl_desc *sg_list = addr;

                                next_dma_addr =
                                        le64_to_cpu((sg_list[SGES_PER_PAGE - 1]).addr);
                        } else {
                                __le64 *prp_list = addr;

                                next_dma_addr = le64_to_cpu(prp_list[last_prp]);
                        }

                        dma_pool_free(dev->prp_page_pool, addr, dma_addr);
                        dma_addr = next_dma_addr;
                }
                mempool_free(iod->sg, dev->iod_mempool);
                nvfs_put_ops();
                return true;
        }
        return false;
}

static blk_status_t nvme_nvfs_map_data(struct nvme_dev *dev, struct request *req,
               struct nvme_command *cmnd, bool *is_nvfs_io)
{
       struct nvme_iod *iod = blk_mq_rq_to_pdu(req);
       struct request_queue *q = req->q;
       enum dma_data_direction dma_dir = rq_dma_dir(req);
       blk_status_t ret = BLK_STS_RESOURCE;
       int nr_mapped;

       nr_mapped = 0;
       *is_nvfs_io = false;

       if (!blk_integrity_rq(req) && nvfs_get_ops()) {
                iod->dma_len = 0;
                iod->sg = mempool_alloc(dev->iod_mempool, GFP_ATOMIC);
                if (!iod->sg) {
                        nvfs_put_ops();
                        return BLK_STS_RESOURCE;
                }

               sg_init_table(iod->sg, blk_rq_nr_phys_segments(req));
               // associates bio pages to scatterlist
               iod->nents = nvfs_ops->nvfs_blk_rq_map_sg(q, req, iod->sg);
               if (!iod->nents) {
                       mempool_free(iod->sg, dev->iod_mempool);
                       nvfs_put_ops();
                       return BLK_STS_IOERR; // reset to original ret
               }
               *is_nvfs_io = true;

               if (unlikely((iod->nents == NVFS_IO_ERR))) {
                       mempool_free(iod->sg, dev->iod_mempool);
                       nvfs_put_ops();
                       pr_err("%s: failed to map sg_nents=:%d\n", __func__, iod->nents);
                       return BLK_STS_IOERR;
               }

               nr_mapped = nvfs_ops->nvfs_dma_map_sg_attrs(dev->dev,
                               iod->sg,
                               iod->nents,
                               dma_dir,
                               DMA_ATTR_NO_WARN);

               if (unlikely((nr_mapped == NVFS_IO_ERR))) {
                       mempool_free(iod->sg, dev->iod_mempool);
                       nvfs_put_ops();
                       pr_err("%s: failed to dma map sglist=:%d\n", __func__, iod->nents);
                       return BLK_STS_IOERR;
               }

               if (unlikely(nr_mapped == NVFS_CPU_REQ)) {
                       mempool_free(iod->sg, dev->iod_mempool);
                       nvfs_put_ops();
                       BUG();
               }

               iod->use_sgl = nvme_pci_use_sgls(dev, req);
               if (iod->use_sgl) { // TBD: not tested on SGL mode supporting drive
                       ret = nvme_pci_setup_sgls(dev, req, &cmnd->rw, nr_mapped);
               } else {
                       // push dma address to hw registers
                       ret = nvme_pci_setup_prps(dev, req, &cmnd->rw);
               }

               if (ret != BLK_STS_OK) {
                       nvme_nvfs_unmap_data(dev, req);
               }

               return ret;
       }
       return ret;
}

#endif /* NVFS_DMA_H */
