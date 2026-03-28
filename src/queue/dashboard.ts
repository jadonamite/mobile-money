import { ExpressAdapter } from "@bull-board/express";
import { createBullBoard } from "@bull-board/api";
import { BullMQAdapter } from "@bull-board/api/dist/queueAdapters/bullMQ";
import { transactionQueue } from "./transactionQueue";
import { providerBalanceAlertQueue } from "./providerBalanceAlertQueue";

const createQueueAdapter = () => {
  return new BullMQAdapter(transactionQueue, {
    readOnlyMode: false,
  });
};

export function createQueueDashboard() {
  const serverAdapter = new ExpressAdapter();

  createBullBoard({
    queues: [
      createQueueAdapter(),
      new BullMQAdapter(providerBalanceAlertQueue, {
        readOnlyMode: false,
      }),
    ],
    serverAdapter: serverAdapter,
    options: {
      uiConfig: {
        boardTitle: "Mobile Money Queue Dashboard",
      },
    },
  });

  serverAdapter.setBasePath("/admin/queues");

  return serverAdapter.getRouter();
}
