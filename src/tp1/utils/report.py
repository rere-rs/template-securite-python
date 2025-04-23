import pygal
from src.tp1.utils.config import logger

class Report:
    def __init__(self, capture, filename, summary):
        self.capture = capture
        self.filename = filename
        self.title = "Protocol Capture Report\n"
        self.summary = summary
        self.array = ""
        self.graph = ""

    def concat_report(self) -> str:
        """
        Concat all data in report
        """
        content = ""
        content += self.title
        content += self.summary
        content += self.array
        content += self.graph

        return content

    def save(self, filename: str) -> None:
        final_content = self.concat_report()
        with open(self.filename, "w") as report:
            report.write(final_content)
        logger.info(f"Report saved in {self.filename}")

    def generate(self, param: str) -> None:
        """
        Generate graph and array
        """
        protocols = self.capture.get_all_protocols()

        if param == "graph":
            # TODO: generate graph
            chart = pygal.Pie()
            chart.title = 'Protocol Distribution'
            for proto, count in protocols.items():
                chart.add(proto, count)

            # Save the chart to a file
            chart_file = self.filename.replace(".pdf", "_chart.svg")
            chart.render_to_file(chart_file)
            self.graph = f"Graph saved to: {chart_file}"
            logger.info(f"Protocol graph generated at {chart_file}")

        elif param == "array":
            # TODO: generate array
            table = "\nProtocole | Nombre de paquets\n"
            table += "-" * 30 + "\n"
            for proto, count in protocols.items():
                table += f"{proto:<10} | {count}\n"
            self.array = table
            logger.info("Protocol table generated")
