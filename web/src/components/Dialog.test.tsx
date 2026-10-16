import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { ConfirmByName } from "./Dialog";

describe("ConfirmByName", () => {
  it("enables the action only when the exact name is typed", async () => {
    const onConfirm = vi.fn();
    const onOpenChange = vi.fn();
    render(
      <ConfirmByName open onOpenChange={onOpenChange} title="Delete secret" description="Gone." name="API_KEY" action="Delete secret" onConfirm={onConfirm} />,
    );
    const button = screen.getByRole("button", { name: "Delete secret" }) as HTMLButtonElement;
    expect(button.disabled).toBe(true);
    const input = screen.getByLabelText(/to confirm/);
    fireEvent.change(input, { target: { value: "api_key" } });
    expect(button.disabled).toBe(true);
    fireEvent.change(input, { target: { value: "API_KEY" } });
    expect(button.disabled).toBe(false);
    fireEvent.click(button);
    await waitFor(() => expect(onConfirm).toHaveBeenCalledOnce());
    await waitFor(() => expect(onOpenChange).toHaveBeenCalledWith(false));
  });
});
