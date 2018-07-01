#include <errno.h>
#include <getopt.h>
#include <libusb-1.0/libusb.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define MY_NAME			"jzboot"

#define INGENIC_VENDOR_ID	0x601A

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

static const uint16_t ingenic_product_ids[] = {
	0x4740,
	0x4750,
	0x4770,
	0x4780,
};

static uint16_t pid;

static unsigned int stage1_load_addr = STAGE1_LOAD_ADDR;
static unsigned int stage2_load_addr = STAGE2_LOAD_ADDR;

static FILE *stage1;
static FILE *stage2;

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

	printf("Usage:\n\t" MY_NAME " [OPTIONS ...] stage1 [program]\n\nOptions:\n");
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

static int cmd_load_data(libusb_device_handle *hdl, FILE *f, uint32_t addr)
{
	int ret, bytes_transferred;
	size_t size, to_read;
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

	/* Send the SET_DATA_LEN command */
	ret = cmd_control(hdl, CMD_SET_DATA_LEN, size);
	if (ret)
		goto out_free;

	/* Send the SET_DATA_ADDR command */
	ret = cmd_control(hdl, CMD_SET_DATA_ADDR, addr);
	if (ret)
		goto out_free;

	/* Upload the data */
	ret = libusb_bulk_transfer(hdl, LIBUSB_ENDPOINT_OUT | 0x1,
			data, (int)size, &bytes_transferred, TIMEOUT_MS);
	if (ret)
		goto out_free;

	if (bytes_transferred != (int)size) {
		ret = -EINVAL;
		goto out_free;
	}

	printf("Uploaded %zu bytes at address 0x%08x\n", size, addr);

out_free:
	free(data);
	return ret;
}

int main(int argc, char **argv)
{
	libusb_context *usb_ctx;
	libusb_device_handle *hdl = NULL;
	int exit_code = EXIT_FAILURE;
	int ret, c;
	unsigned int i;
	char *end;

	while ((c = getopt_long(argc, argv, "+ha:b:", options, NULL)) != -1) {
		switch (c) {
		case 'h':
			usage();
			return EXIT_SUCCESS;
		case 'a':
			stage1_load_addr = strtol(optarg, &end, 16);
			if (optarg == end) {
				fprintf(stderr, "Unable to parse stage1 addr\n");
				return EXIT_FAILURE;
			}
			break;
		case 'b':
			stage2_load_addr = strtol(optarg, &end, 16);
			if (optarg == end) {
				fprintf(stderr, "Unable to parse stage2 addr\n");
				return EXIT_FAILURE;
			}
			break;
		case '?':
			return EXIT_FAILURE;
		}
	}

	if (optind == argc || argc > optind + 2) {
		fprintf(stderr, "Unable to parse arguments.\n");
		usage();
		return EXIT_FAILURE;
	}

	stage1 = fopen(argv[optind], "r");
	if (!stage1) {
		fprintf(stderr, "Unable to open stage1 program\n");
		return EXIT_FAILURE;
	}

	if (argc == optind + 2) {
		stage2 = fopen(argv[optind + 1], "r");
		if (!stage2) {
			fprintf(stderr, "Unable to open stage2 program\n");
			return EXIT_FAILURE;
		}
	}

	ret = libusb_init(&usb_ctx);
	if (ret) {
		fprintf(stderr, "Unable to init libusb\n");
		goto out_close_files;
	}

	for (i = 0; !hdl && i < ARRAY_SIZE(ingenic_product_ids); i++) {
		hdl = libusb_open_device_with_vid_pid(usb_ctx,
			INGENIC_VENDOR_ID, ingenic_product_ids[i]);
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

	ret = cmd_load_data(hdl, stage1, stage1_load_addr);
	if (ret) {
		fprintf(stderr, "Unable to upload stage1 bootloader\n");
		goto out_close_dev_handle;
	}

	ret = cmd_control(hdl, CMD_START1, stage1_load_addr);
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

	ret = cmd_load_data(hdl, stage2, stage2_load_addr);
	if (ret) {
		fprintf(stderr, "Unable to upload stage2 program\n");
		goto out_close_dev_handle;
	}

	ret = cmd_control(hdl, CMD_FLUSH_CACHES, 0);
	if (ret) {
		fprintf(stderr, "Unable to flush caches\n");
		goto out_close_dev_handle;
	}

	ret = cmd_control(hdl, CMD_START2, stage2_load_addr);
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
	return exit_code;
}
