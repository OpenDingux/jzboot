#include <errno.h>
#include <getopt.h>
#include <libusb-1.0/libusb.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <endian.h>

#define MY_NAME			"jzboot"

#define STAGE1_LOAD_ADDR	0x80000000
#define STAGE2_LOAD_ADDR	0x81000000

#define TIMEOUT_MS		5000

#define ARRAY_SIZE(x) (sizeof(x) ? sizeof(x) / sizeof((x)[0]) : 0)

enum commands {
	CMD_GET_CPU_INFO,
	CMD_SET_DATA_ADDR,
	CMD_SET_DATA_LEN,
	CMD_FLUSH_CACHES,
	CMD_START1,
	CMD_START2,
};

static const uint16_t ingenic_ids[] = {
	0x601a,
	0xa108,
};

static const uint16_t ingenic_product_ids[] = {
	0x4740,
	0x4750,
	0x4760,
	0x4770,
	0x4780,
};

static uint16_t pid;

static unsigned int stage1_load_addr = STAGE1_LOAD_ADDR;
static unsigned int stage2_load_addr = STAGE2_LOAD_ADDR;
static unsigned int stage1_exec_addr = STAGE1_LOAD_ADDR;
static unsigned int stage2_exec_addr = STAGE2_LOAD_ADDR;

static FILE *stage1;
static FILE *stage2;
static FILE *devicetree;

static const struct option options[] = {
	{"help", no_argument, 0, 'h'},
	{"stage1-addr", required_argument, 0, 'a'},
	{"stage2-addr", required_argument, 0, 'b'},
	{0, 0, 0, 0},
};

static const char *options_descriptions[] = {
	"Show this help and quit.",
	"Set the load and boot address of the 1st-stage bootloader.",
	"Set the load and boot address of the program.",
};

static void usage(void)
{
	unsigned int i;

	printf("Usage:\n\t" MY_NAME " [OPTIONS ...] stage1 [kernel] [devicetree]\n\nOptions:\n");
	for (i = 0; options[i].name; i++)
		printf("\t-%c, --%s\n\t\t\t%s\n",
					options[i].val, options[i].name,
					options_descriptions[i]);
}

static int cmd_get_info(libusb_device_handle *hdl)
{
	unsigned char info[8];

	int ret;

	ret = libusb_control_transfer(hdl, LIBUSB_ENDPOINT_IN |
			LIBUSB_REQUEST_TYPE_VENDOR | LIBUSB_RECIPIENT_DEVICE,
			CMD_GET_CPU_INFO, 0, 0, info, sizeof(info), TIMEOUT_MS);

	if (ret != sizeof(info))
		return -EIO;

	return 0;
}

static int cmd_control(libusb_device_handle *hdl, uint32_t cmd, uint32_t attr)
{
	return libusb_control_transfer(hdl, LIBUSB_ENDPOINT_OUT |
			LIBUSB_REQUEST_TYPE_VENDOR | LIBUSB_RECIPIENT_DEVICE,
			cmd, (attr >> 16) & 0xffff, attr & 0xffff,
			NULL, 0, TIMEOUT_MS);
}

/* NOTE: big endian fields */
struct uimage_header {
	uint32_t magic;    /* Magic number (UIMAGE_MAGIC) */
	uint32_t hcrc;     /* Image header CRC */
	uint32_t time;     /* Image creation timestamp */
	uint32_t size;     /* Image data size */
	uint32_t load;     /* Data load address */
	uint32_t ep;       /* Entry point address */
	uint32_t dcrc;     /* Image data CRC */
	uint8_t  os;       /* Operating system */
	uint8_t  arch;     /* CPU architecture */
	uint8_t  type;     /* Image type */
	uint8_t  comp;     /* Compression type */
	uint8_t  name[32]; /* Image name */
} __attribute__((packed));

#define UIMAGE_MAGIC         0x27051956
#define UIMAGE_ARCH_MIPS     5
#define UIMAGE_COMPRESS_NONE 0

static int check_and_process_uimage_hdr(char **data, size_t *size,
					unsigned int *load_addr,
					unsigned int *exec_addr)
{
	struct uimage_header *hdr = (struct uimage_header *)(*data);

	if (*size < sizeof(struct uimage_header))
		return -EINVAL;

	if (be32toh(hdr->magic) != UIMAGE_MAGIC)
		return 0; /* not an uimage */

	if (hdr->arch != UIMAGE_ARCH_MIPS) {
		fprintf(stderr, "UIMAGE: Unsupported architecture %02x\n", hdr->arch);
		return -ENOTSUP;
	}
	if (hdr->comp != UIMAGE_COMPRESS_NONE) {
		fprintf(stderr, "UIMAGE: loading compressed images not implemented\n");
		return -ENOSYS;
	}

	*load_addr = be32toh(hdr->load);
	*exec_addr = be32toh(hdr->ep);
	*size -= sizeof(struct uimage_header);
	*data += sizeof(struct uimage_header);
	return 0;
}

static void skip_stage1_image_header(const unsigned char *data,
				     unsigned int *exec_addr)
{
	const uint32_t *header_ptr = (const uint32_t*)data;

	if (le32toh(header_ptr[0]) == 0x4d53504c)
		/* `MSPL` header (jz4760+, jz4725b) */
		*exec_addr += 4;
	else if (le32toh(header_ptr[1]) == 0x55555555)
		/* jz4750 header */
		*exec_addr += 12;
	else
		/* assume no header or it just does NOPs (jz4740) */
		;
	return;
}

static int cmd_load_data(libusb_device_handle *hdl, FILE *f,
			 uint32_t addr, size_t *data_size)
{
	int ret, bytes_transferred;
	size_t size, to_read, to_write;
	unsigned char *data;
	char *ptr;

	/* Get the file size */
	fseek(f, 0, SEEK_END);
	size = ftell(f);
	fseek(f, 0, SEEK_SET);

	data = malloc(size);
	if (!data)
		return -ENOMEM;

	ptr = (char *)data;
	to_read = size;
	do {
		size_t bytes_read = fread(ptr, 1, to_read, f);
		if (!bytes_read) {
			ret = -EIO;
			goto out_free;
		}

		ptr += bytes_read;
		to_read -= bytes_read;
	} while (to_read > 0);

	ptr = (char *)data;
	if (addr == stage1_load_addr)
		skip_stage1_image_header(ptr, &stage1_exec_addr);
	else if (addr == stage2_load_addr) {
		ret = check_and_process_uimage_hdr(&ptr, &size,
					&addr, &stage2_exec_addr);
		if (ret)
			goto out_free;
	}

	if (data_size)
		*data_size = size;

	/* Send the SET_DATA_LEN command */
	ret = cmd_control(hdl, CMD_SET_DATA_LEN, size);
	if (ret)
		goto out_free;

	/* Send the SET_DATA_ADDR command */
	ret = cmd_control(hdl, CMD_SET_DATA_ADDR, addr);
	if (ret)
		goto out_free;

	to_write = size;

	do {
		ret = libusb_bulk_transfer(hdl, LIBUSB_ENDPOINT_OUT | 0x1,
					   ptr, (int)to_write,
					   &bytes_transferred, TIMEOUT_MS);
		if (ret)
			goto out_free;

		to_write -= bytes_transferred;
		ptr += bytes_transferred;
	} while (to_write > 0);

	printf("Uploaded %lu bytes at address 0x%08x\n",
	       (unsigned long)size, addr);

out_free:
	free(data);
	return ret;
}

int main(int argc, char **argv)
{
	libusb_context *usb_ctx;
	libusb_device_handle *hdl = NULL;
	int exit_code = EXIT_FAILURE;
	size_t kernel_size;
	unsigned int i, j;
	int ret, c;
	char *end;

	while ((c = getopt_long(argc, argv, "+ha:b:", options, NULL)) != -1) {
		switch (c) {
		case 'h':
			usage();
			return EXIT_SUCCESS;
		case 'a':
			stage1_load_addr = strtol(optarg, &end, 16);
			stage1_exec_addr = stage1_load_addr;
			if (optarg == end) {
				fprintf(stderr, "Unable to parse stage1 addr\n");
				return EXIT_FAILURE;
			}
			break;
		case 'b':
			stage2_load_addr = strtol(optarg, &end, 16);
			stage2_exec_addr = stage2_load_addr;
			if (optarg == end) {
				fprintf(stderr, "Unable to parse stage2 addr\n");
				return EXIT_FAILURE;
			}
			break;
		case '?':
			return EXIT_FAILURE;
		}
	}

	if (optind == argc || argc > optind + 3) {
		fprintf(stderr, "Unable to parse arguments.\n");
		usage();
		return EXIT_FAILURE;
	}

	stage1 = fopen(argv[optind], "rb");
	if (!stage1) {
		fprintf(stderr, "Unable to open stage1 program\n");
		return EXIT_FAILURE;
	}

	if (argc >= optind + 2) {
		stage2 = fopen(argv[optind + 1], "rb");
		if (!stage2) {
			fprintf(stderr, "Unable to open stage2 program\n");
			return EXIT_FAILURE;
		}
	}

	if (argc >= optind + 3) {
		devicetree = fopen(argv[optind + 2], "rb");
		if (!devicetree) {
			fprintf(stderr, "Unable to open devicetree\n");
			return EXIT_FAILURE;
		}
	}

	ret = libusb_init(&usb_ctx);
	if (ret) {
		fprintf(stderr, "Unable to init libusb\n");
		goto out_close_files;
	}

	for (j = 0; !hdl && j < ARRAY_SIZE(ingenic_ids); j++) {
		for (i = 0; !hdl && i < ARRAY_SIZE(ingenic_product_ids); i++) {
			hdl = libusb_open_device_with_vid_pid(usb_ctx,
				ingenic_ids[j], ingenic_product_ids[i]);
		}
	}


	if (!hdl) {
		fprintf(stderr, "Unable to find Ingenic device.\n");
		goto out_exit_libusb;
	}

	pid = ingenic_product_ids[i - 1];

	ret = libusb_claim_interface(hdl, 0);
	if (ret) {
		fprintf(stderr, "Unable to claim interface 0\n");
		goto out_close_dev_handle;
	}

	if (cmd_get_info(hdl)) {
		fprintf(stderr, "Unable to read CPU info\n");
		goto out_close_dev_handle;
	}

	printf("Found Ingenic JZ%x based device\n", pid);

	ret = cmd_load_data(hdl, stage1, stage1_load_addr, NULL);
	if (ret) {
		fprintf(stderr, "Unable to upload stage1 bootloader\n");
		goto out_close_dev_handle;
	}

	ret = cmd_control(hdl, CMD_START1, stage1_exec_addr);
	if (ret) {
		fprintf(stderr, "Unable to execute stage1 bootloader\n");
		goto out_close_dev_handle;
	}

	if (!stage2)
		goto out_complete;

	printf("Waiting for stage1 bootloader to complete operation...\n");
	for (i = 0; i < 100; i++) {
		if (!cmd_get_info(hdl))
			break;

		usleep(10000); /* 10ms * 100 = 1s */
	}

	if (i == 100) {
		fprintf(stderr, "Stage1 bootloader did not return.\n");
		goto out_close_dev_handle;
	}

	ret = cmd_load_data(hdl, stage2, stage2_load_addr, &kernel_size);
	if (ret) {
		fprintf(stderr, "Unable to upload stage2 program\n");
		goto out_close_dev_handle;
	}

	if (devicetree) {
		ret = cmd_load_data(hdl, devicetree,
				    stage2_load_addr + kernel_size, NULL);
		if (ret) {
			fprintf(stderr, "Unable to upload devicetree\n");
			goto out_close_dev_handle;
		}
	}

	ret = cmd_control(hdl, CMD_FLUSH_CACHES, 0);
	if (ret) {
		fprintf(stderr, "Unable to flush caches\n");
		goto out_close_dev_handle;
	}

	ret = cmd_control(hdl, CMD_START2, stage2_exec_addr);
	if (ret) {
		fprintf(stderr, "Unable to execute program\n");
		goto out_close_dev_handle;
	}

out_complete:
	printf("Operation complete.\n");
	exit_code = EXIT_SUCCESS;
out_close_dev_handle:
	libusb_close(hdl);
out_exit_libusb:
	libusb_exit(usb_ctx);
out_close_files:
	fclose(stage1);
	if (stage2)
		fclose(stage2);
	if (devicetree)
		fclose(devicetree);
	return exit_code;
}
